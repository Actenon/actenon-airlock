"""Runner for Field Test 3: Adversarial Transport Boundary Evaluation.

Executes all 6 transport vectors against a target host:
1. Standard requests.delete()
2. urllib.request with method DELETE
3. http.client.HTTPConnection with method DELETE
4. Raw Python socket sending raw HTTP DELETE
5. Subprocess invoking curl
6. Dynamically imported Python code
"""

import subprocess
import sys
from pathlib import Path

def run_suite(target_url: str = "http://127.0.0.1:8088/critical-resource"):
    transports_dir = Path(__file__).parent / "transports"
    results = {}

    print(f"=== Running Field Test 3 Transport Escape Suite against {target_url} ===")
    for script in sorted(transports_dir.glob("exp*.py")):
        print(f"\n--- Running {script.name} ---")
        res = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        print(res.stdout)
        if res.stderr:
            print("Stderr:", res.stderr.strip())
        results[script.name] = res.returncode

    print("\n=== Transport Suite Completed ===")
    print("Return codes:", results)

if __name__ == "__main__":
    run_suite()
