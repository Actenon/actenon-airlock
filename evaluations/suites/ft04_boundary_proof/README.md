# Field Test 4: Prove the Boundary Without False Positives

## Objective
Demonstrate both facts in the **SAME** Protected Mode container session:
- **POSITIVE:** An approved model inference request completes successfully through Airlock's trusted supervisor.
- **NEGATIVE:** The agent cannot execute an unauthorized external `DELETE` operation through any available transport (`requests`, `urllib`, `http.client`, raw `socket`, `curl`).

## Methodology
1. **Control Container Proof:** In an unrestricted container connected to the Docker test network, all 5 transports are executed to confirm the mock endpoint is functional and reachable.
2. **Protected Container Test:** In the Airlock Protected Mode container (`--network none`), the identical attack implementations are executed.
3. **Supervisor Bridge Test:** The authorized OpenAI text-completion model request crosses the supervisor IPC bridge and successfully receives a synthetic response.

## Artifacts
- `docker_mock_server.py`: Mock service providing `/health`, `/critical-resource`, and `/__audit`.
- `control_transports.py`: Script executing all 5 transports in the control container.
- `protected_agent_main.py`: The single reviewed agent source executing both the positive inference and negative transport attacks.
- Full audit report in `evaluations/reports/04_container_boundary_proof.md`.
