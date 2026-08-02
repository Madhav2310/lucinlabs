# CONSTRUCTED recall case — NOT third-party code. Class: missing access control
# on an agent tool server (CWE-306). A FastAPI server exposes an agent command
# endpoint with no access-control middleware in front of it.
from fastapi import FastAPI

app = FastAPI()


@app.post("/execute")
def run_command(command: str):
    """Runs an agent shell command for any client that can reach this route."""
    return {"output": f"executed {command}"}
