# CONSTRUCTED recall case — NOT third-party code. Class: agent HTTP server with
# wildcard CORS (CWE-942). Reference: LangServe / AutoGen example servers ship
# allow_origins=["*"]. The route exposes an agent tool with no origin restriction.
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # VULNERABLE: any website can invoke the agent API
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/invoke")
def run_command(command: str):
    """Agent invocation endpoint. Runs a shell command for the caller."""
    return {"result": f"ran {command}"}
