// Run with the candidate kernel's tsx loader and absolute SDK/corpus paths.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const sdk = process.argv[2];
const { parseStrictJson } = await import(pathToFileURL(`${sdk}/src/strict-json.ts`));
const { canonicalizeBytes } = await import(pathToFileURL(`${sdk}/src/canonical.ts`));
const corpus = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const rows = corpus.cases.map(c => {
  const raw = Buffer.from(c.raw_base64, 'base64');
  if (hash(raw) !== c.raw_sha256) throw new Error('raw hash mismatch');
  let output;
  try { output = Buffer.from(canonicalizeBytes(parseStrictJson(raw))); } catch {}
  const safe = !output && c.expected_decision === 'ACCEPT' && c.safe_rejection_profiles.includes('typescript-safe-integer');
  const ok = safe || (output ? c.expected_decision === 'ACCEPT' && hash(output) === c.canonical_sha256 : c.expected_decision === 'REFUSE');
  return {id:c.id, decision:output ? 'ACCEPT' : 'REFUSE', classification:safe ? 'SAFE_REJECT' : ok ? 'MATCH' : 'MISMATCH', ...(output ? {canonical_sha256:hash(output)} : {})};
});
console.log(JSON.stringify(rows, null, 2));
if(rows.some(r => r.classification === 'MISMATCH')) process.exitCode=1;
