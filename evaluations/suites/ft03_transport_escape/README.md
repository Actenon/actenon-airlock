# Field Test 3: Actual Security Boundary Escape Test

## Objective
Establish whether an untrusted agent can send an unauthorized `DELETE` request through transport mechanisms that Airlock does not wrap by default.

## Experiments
1. `requests.delete()`
2. `urllib.request`
3. `http.client.HTTPConnection`
4. Raw POSIX `socket`
5. `subprocess.run(["curl", ...])`
6. Dynamic import & execution (`importlib`, `exec`)
7. Approval separation & self-signing attack

## Key Finding
- In **Local Mode**, Airlock cooperatively wraps `requests` and `httpx`. Transports bypassing Python runtime hooks (`socket`, `curl`, raw `urllib`) can escape unless Protected Mode is enabled.
- In **Protected Mode**, containerization with `--network none` physically prevents all outbound raw socket connections and curl subprocesses from reaching the external network.
- Full details in `evaluations/reports/03_transport_escape_eval.md`.
