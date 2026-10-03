"""Run the local server in ../server.py, then use Airlock from this directory."""

import requests

response = requests.post("http://127.0.0.1:8765/events", json={"message": "hello"})
response.raise_for_status()
print(response.json())
