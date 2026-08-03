# CONSTRUCTED recall case — NOT third-party code. Class: missing access control
# on an agent tool server (CWE-306) on Flask. The route exposes an agent command
# runner with no access-control middleware in front of it.
from flask import Flask, request

app = Flask(__name__)


@app.post("/invoke")
def run_command():
    """Runs an agent shell command for any client that can reach this route."""
    command = request.json["command"]
    return {"result": f"ran {command}"}
