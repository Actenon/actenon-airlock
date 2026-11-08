// airlock_verify: an independent offline verifier for Actenon Airlock receipt journals.
//
// It shares no code with Airlock. It uses only the Go standard library (crypto/ed25519,
// crypto/sha256, encoding/json, encoding/base64), and reimplements the canonical JSON encoding
// that Airlock signs: Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=True).
//
// For one journal it checks:
//   - each line is the canonical encoding of its own JSON object;
//   - each line's "prev" is the SHA-256 (hex) of the previous line's exact bytes (the first is null);
//   - each Ed25519 signature verifies, against a public key you supply, over
//     "actenon-airlock/receipt/v1\n" + canonical(row without "signature");
//   - optionally, a signed checkpoint ("actenon-airlock/journal-checkpoint/v1\n" + canonical(payload))
//     that attests the journal's length and head: truncation, rollback and a substituted
//     journal are detected; entries appended after the checkpoint are reported, not trusted.
//
// What it does NOT check, by design, and reports as such:
//   - the nested observer signatures inside reconciliation receipts (counted separately);
//   - whether any external effect really happened. A valid signature proves what Airlock
//     recorded, not what a provider did. Provider truth needs the provider's own record.
//
// Usage:
//
//	go run airlock_verify.go -journal receipts.jsonl -public-key public-key.json [-checkpoint checkpoint.json] [-expect-key BASE64]
//
// Exit status: 0 when every check passed, 1 when any failed, 2 on a usage or input error.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	receiptSchema    = "actenon-airlock/receipt/v1"
	receiptDomain    = "actenon-airlock/receipt/v1\n"
	checkpointSchema = "actenon-airlock/journal-checkpoint/v1"
	checkpointDomain = "actenon-airlock/journal-checkpoint/v1\n"
)

// canonical mirrors Python's json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
// for values decoded with json.Decoder.UseNumber (numbers keep their exact literal text).
func canonical(v any, out *bytes.Buffer) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if x {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		out.WriteString(string(x))
	case string:
		writeString(x, out)
	case []any:
		out.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := canonical(e, out); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // UTF-8 byte order equals Python's code-point order
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(k, out)
			out.WriteByte(':')
			if err := canonical(x[k], out); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}

// writeString escapes as Python's ensure_ascii encoder does: \" \\ \b \f \n \r \t as short
// escapes, every other character outside printable ASCII (0x20-0x7e) as lowercase \uXXXX,
// with UTF-16 surrogate pairs above U+FFFF.
func writeString(s string, out *bytes.Buffer) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r >= 0x20 && r <= 0x7e {
				out.WriteRune(r)
			} else if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(out, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(out, `\u%04x`, r)
			}
		}
	}
	out.WriteByte('"')
}

func decode(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	err := canonical(v, &buf)
	return buf.Bytes(), err
}

type lineResult struct {
	Line    int    `json:"line"`
	Stage   string `json:"stage,omitempty"`
	OK      bool   `json:"ok"`
	Problem string `json:"problem,omitempty"`
}

type report struct {
	Schema                string       `json:"schema"`
	Journal               string       `json:"journal"`
	Entries               int          `json:"entries"`
	Verified              int          `json:"verified"`
	IntegrityOK           bool         `json:"integrity_ok"`
	ChainHeadSHA256       *string      `json:"chain_head_sha256"`
	PublicKeySHA256       string       `json:"public_key_sha256"`
	Completeness          string       `json:"completeness"`
	CompletenessDetail    string       `json:"completeness_detail"`
	ObserverRowsUnchecked int          `json:"reconciliation_rows_observer_signature_not_checked"`
	ProviderTruth         string       `json:"provider_truth"`
	Problems              []lineResult `json:"problems"`
}

func readKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Key == "" {
		return nil, fmt.Errorf("public key file must be {\"key\": \"<base64>\"}")
	}
	return parseKey(doc.Key)
}

func parseKey(b64 string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is not 32 bytes of standard base64")
	}
	return ed25519.PublicKey(key), nil
}

func verifyJournal(lines [][]byte, key ed25519.PublicKey) (int, []lineResult, *string, int) {
	var prev *string
	verified, observer := 0, 0
	var problems []lineResult
	for i, line := range lines {
		res := lineResult{Line: i + 1}
		problem := ""
		v, err := decode(line)
		row, isObj := v.(map[string]any)
		if err != nil || !isObj {
			problem = "unreadable receipt line"
		}
		if problem == "" {
			if s, ok := row["stage"].(string); ok {
				res.Stage = s
				if s == "reconciliation-requested" || s == "reconciled" {
					observer++
				}
			}
			canon, cerr := encode(row)
			sig, sigOK := row["signature"].(map[string]any)
			switch {
			case cerr != nil:
				problem = "cannot canonicalise: " + cerr.Error()
			case !bytes.Equal(canon, line):
				problem = "line is not in canonical form"
			case row["schema"] != receiptSchema:
				problem = "unsupported receipt schema"
			case !sigOK || sig["algorithm"] != "EdDSA" || sig["encoding"] != "base64url":
				problem = "missing or unsupported signature"
			case row["signer_key_id"] != nil && row["signer_key_id"] != sig["key_id"]:
				problem = "signature key id differs from signer_key_id"
			}
			if problem == "" {
				wantPrev := any(nil)
				if prev != nil {
					wantPrev = *prev
				}
				if row["prev"] != wantPrev {
					problem = "hash chain broken (a receipt was removed, reordered or edited)"
				}
			}
			if problem == "" {
				value, _ := sig["value"].(string)
				rawSig, derr := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
				unsigned := map[string]any{}
				for k, val := range row {
					if k != "signature" {
						unsigned[k] = val
					}
				}
				body, _ := encode(unsigned)
				msg := append([]byte(receiptDomain), body...)
				if derr != nil || len(rawSig) != ed25519.SignatureSize || !ed25519.Verify(key, msg, rawSig) {
					problem = "signature does not verify against the supplied public key"
				}
			}
		}
		sum := sha256.Sum256(line)
		h := hex.EncodeToString(sum[:])
		prev = &h
		if problem == "" {
			verified++
		} else {
			res.Problem = problem
			problems = append(problems, res)
		}
	}
	return verified, problems, prev, observer
}

func checkpointStatus(path string, key ed25519.PublicKey, lines [][]byte) (string, string) {
	if path == "" {
		return "UNANCHORED", "no checkpoint supplied: truncation or rollback of the journal cannot be detected"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "INVALID_CHECKPOINT", err.Error()
	}
	v, err := decode(bytes.TrimSpace(raw))
	env, ok := v.(map[string]any)
	if err != nil || !ok {
		return "INVALID_CHECKPOINT", "checkpoint is not a JSON object"
	}
	payload, ok := env["payload"].(map[string]any)
	sigText, ok2 := env["signature"].(string)
	if !ok || !ok2 || payload["schema"] != checkpointSchema {
		return "INVALID_CHECKPOINT", "checkpoint is missing its payload, signature or schema"
	}
	body, err := encode(payload)
	sig, derr := base64.StdEncoding.Strict().DecodeString(sigText)
	if err != nil || derr != nil || !ed25519.Verify(key, append([]byte(checkpointDomain), body...), sig) {
		return "INVALID_CHECKPOINT", "checkpoint signature does not verify against the supplied public key"
	}
	n, err := payload["journal_entries"].(json.Number).Int64()
	if err != nil || n < 0 {
		return "INVALID_CHECKPOINT", "journal_entries is not a non-negative integer"
	}
	if int64(len(lines)) < n {
		return "TRUNCATED", fmt.Sprintf("journal has %d entries; the checkpoint attests %d", len(lines), n)
	}
	var head any
	if n > 0 {
		sum := sha256.Sum256(lines[n-1])
		head = hex.EncodeToString(sum[:])
	}
	if payload["chain_head_sha256"] != head {
		return "MISMATCH", "the journal's entry at the checkpoint does not match the attested head (rolled back or substituted)"
	}
	if int64(len(lines)) > n {
		return "ANCHORED_PREFIX", fmt.Sprintf("first %d entries anchored; %d later entries are not covered by the checkpoint", n, int64(len(lines))-n)
	}
	return "ANCHORED", fmt.Sprintf("all %d entries anchored by the checkpoint", n)
}

func main() {
	journal := flag.String("journal", "", "receipts.jsonl")
	keyPath := flag.String("public-key", "", "public-key.json")
	checkpoint := flag.String("checkpoint", "", "checkpoint.json (optional)")
	expect := flag.String("expect-key", "", "base64 public key the journal must use (an independent pin)")
	flag.Parse()
	if *journal == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: airlock_verify -journal receipts.jsonl -public-key public-key.json [-checkpoint checkpoint.json] [-expect-key BASE64]")
		os.Exit(2)
	}
	key, err := readKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *expect != "" {
		pinned, err := parseKey(*expect)
		if err != nil || !bytes.Equal(pinned, key) {
			fmt.Fprintln(os.Stderr, "the journal's public key differs from the expected pinned key")
			os.Exit(1)
		}
	}
	f, err := os.Open(*journal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()
	var lines [][]byte
	raw, _ := os.ReadFile(*journal)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	verified, problems, head, observer := verifyJournal(lines, key)
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		problems = append(problems, lineResult{Line: len(lines), Problem: "journal ends with an incomplete line"})
	}
	status, detail := checkpointStatus(*checkpoint, key, lines)
	keySum := sha256.Sum256(key)
	r := report{
		Schema:                "actenon-airlock/independent-verification/v1",
		Journal:               *journal,
		Entries:               len(lines),
		Verified:              verified,
		IntegrityOK:           len(problems) == 0,
		ChainHeadSHA256:       head,
		PublicKeySHA256:       hex.EncodeToString(keySum[:]),
		Completeness:          status,
		CompletenessDetail:    detail,
		ObserverRowsUnchecked: observer,
		ProviderTruth:         "NOT ESTABLISHED by this verifier: signatures prove what Airlock recorded, not what a provider did",
		Problems:              problems,
	}
	if r.Problems == nil {
		r.Problems = []lineResult{}
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	bad := !r.IntegrityOK || status == "TRUNCATED" || status == "MISMATCH" || status == "INVALID_CHECKPOINT"
	if bad {
		os.Exit(1)
	}
}
