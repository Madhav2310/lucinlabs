"""Tests for the dataflow detectors added to close recall gaps:
AG-SSRF, AG-DESERIALIZE, AG-PATH-TRAVERSAL (gated), and the AG-DOCKER-EXEC
variable-assembled-command fix.

Precision is sacred (flagship = 0.0% FP / 52 repos), so every detector has
BOTH fires-on-vuln and does-not-fire-on-benign assertions.
"""

import tempfile
import textwrap

from lucin.detectors.docker_exec import detect_docker_exec
from lucin.detectors.insecure_deserialization import detect_insecure_deserialization
from lucin.detectors.path_traversal import detect_path_traversal
from lucin.detectors.ssrf import detect_ssrf
from lucin.models import Agent, Tool, ToolCapability


def _agent_with_source(source: str, tool_name: str = "the_tool") -> Agent:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(textwrap.dedent(source))
        path = f.name
    tool = Tool(name=tool_name, capabilities=[ToolCapability.NETWORK_ACCESS],
                source_file=path, source_line=1)
    return Agent(name="test_agent", source_file=path, tools=[tool])


# ---------------------------------------------------------------------------
# AG-SSRF
# ---------------------------------------------------------------------------

def test_ssrf_tainted_host_in_fstring_fires():
    src = """\
        import requests
        def check_service_health(host: str, port: int) -> bool:
            requests.get(f"http://{host}:{port}/health", timeout=2)
            return True
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_url_via_hostinjection_variable_fires():
    src = """\
        import requests
        def fetch(host: str) -> str:
            u = f"https://{host}/data"
            return requests.get(u).text
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_constant_host_with_tainted_path_does_not_fire():
    # host is fixed; only the PATH/query is tainted → not SSRF (benign vendor-API shape)
    src = """\
        import requests
        def get_city_weather(city: str) -> str:
            return requests.get(f"https://api.weather.com/v1/{city}").text
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert not any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_constant_host_then_endpoint_param_does_not_fire():
    # f"https://oapi.vendor.com{endpoint}" — host fixed, endpoint is the path (dingtalk shape)
    src = """\
        import requests
        def call_api(endpoint: str, token: str):
            url = f"https://oapi.vendor.com{endpoint}?token={token}"
            return requests.get(url)
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert not any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_bare_param_url_does_not_fire():
    # Bare param URL is indistinguishable from benign "fetch this page" tools → not flagged.
    src = """\
        import requests
        def visit_webpage(url: str) -> str:
            return requests.get(url).text
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert not any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_private_method_does_not_fire():
    src = """\
        import requests
        def _wait_for_server(self, host: str, token: str):
            requests.get(f"https://{host}/api?token={token}")
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert not any(f.id == "AG-SSRF" for f in findings)


def test_ssrf_hardcoded_url_does_not_fire():
    src = """\
        import requests
        def ping() -> str:
            return requests.get("https://example.com/health").text
    """
    findings = detect_ssrf(_agent_with_source(src))
    assert not any(f.id == "AG-SSRF" for f in findings)


# ---------------------------------------------------------------------------
# AG-DESERIALIZE
# ---------------------------------------------------------------------------

def test_deser_pickle_loads_fires():
    src = """\
        import pickle
        def load_session(blob: bytes):
            return pickle.loads(blob)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_base64_pickle_via_intermediate_fires():
    src = """\
        import base64, pickle
        def load_tool_result(encoded: str):
            raw = base64.b64decode(encoded)
            return pickle.loads(raw)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_yaml_unsafe_loader_fires():
    src = """\
        import yaml
        def load_config(config_text: str) -> dict:
            return yaml.load(config_text, Loader=yaml.Loader)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_yaml_safeloader_does_not_fire():
    src = """\
        import yaml
        def load_config(config_text: str) -> dict:
            return yaml.load(config_text, Loader=yaml.SafeLoader)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_yaml_safe_load_does_not_fire():
    src = """\
        import yaml
        def load_config(config_text: str) -> dict:
            return yaml.safe_load(config_text)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_json_loads_does_not_fire():
    src = """\
        import json
        def load_data(blob: str):
            return json.loads(blob)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


def test_deser_private_method_does_not_fire():
    src = """\
        import pickle, base64
        def _deserialize(encoded_value: str, allow_pickle: bool = False):
            if not allow_pickle:
                raise ValueError("rejected")
            return pickle.loads(base64.b64decode(encoded_value[7:]))
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


# ---------------------------------------------------------------------------
# AG-PATH-TRAVERSAL  (sound but intentionally NOT registered — unit-tested only)
# ---------------------------------------------------------------------------

def test_path_traversal_open_read_fires():
    src = """\
        def read_document(path: str) -> str:
            with open(path) as f:
                return f.read()
    """
    findings = detect_path_traversal(_agent_with_source(src))
    assert any(f.id == "AG-PATH-TRAVERSAL" for f in findings)


def test_path_traversal_naive_join_fires():
    src = """\
        import os
        def serve_file(filename: str) -> bytes:
            full = os.path.join("./agent_data", filename)
            with open(full, "rb") as f:
                return f.read()
    """
    findings = detect_path_traversal(_agent_with_source(src))
    assert any(f.id == "AG-PATH-TRAVERSAL" for f in findings)


def test_path_traversal_pathlib_fstring_fires():
    src = """\
        from pathlib import Path
        def load_template(template_name: str) -> str:
            return Path(f"templates/{template_name}").read_text()
    """
    findings = detect_path_traversal(_agent_with_source(src))
    assert any(f.id == "AG-PATH-TRAVERSAL" for f in findings)


def test_path_traversal_with_containment_does_not_fire():
    src = """\
        import os
        def read_file(file_name: str) -> str:
            safe, file_path = self._check_path(file_name, self.base_dir, True)
            if not safe:
                return "denied"
            return open(file_path).read()
    """
    findings = detect_path_traversal(_agent_with_source(src))
    assert not any(f.id == "AG-PATH-TRAVERSAL" for f in findings)


def test_path_traversal_not_registered_in_run_all():
    # The detector is deliberately excluded from run_all_detectors (0% FP guarantee).
    from lucin.detectors import run_all_detectors
    src = """\
        def read_document(path: str) -> str:
            with open(path) as f:
                return f.read()
    """
    agent = _agent_with_source(src)
    findings = run_all_detectors([agent])
    assert not any(f.id == "AG-PATH-TRAVERSAL" for f in findings)


# ---------------------------------------------------------------------------
# AG-DOCKER-EXEC — variable-assembled command fix
# ---------------------------------------------------------------------------

def _exec_agent(source: str) -> Agent:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(textwrap.dedent(source))
        path = f.name
    tool = Tool(name="exec_tool", capabilities=[ToolCapability.EXECUTE_CODE],
                source_file=path, source_line=1)
    return Agent(name="test_agent", source_file=path, tools=[tool])


def test_docker_run_via_variable_fstring_fires():
    src = """\
        import subprocess
        def execute_task(image: str) -> str:
            cmd = f"docker run --privileged --network=host {image}"
            return subprocess.check_output(cmd, shell=True, text=True)
    """
    findings = detect_docker_exec(_exec_agent(src))
    assert any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_docker_run_via_variable_concat_fires():
    src = """\
        import subprocess
        def run_job(image: str) -> str:
            cmd = "docker run " + image
            return subprocess.check_output(cmd, shell=True)
    """
    findings = detect_docker_exec(_exec_agent(src))
    assert any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_non_docker_variable_command_does_not_fire():
    src = """\
        import subprocess
        def list_dir(path: str) -> str:
            cmd = "ls -la " + path
            return subprocess.check_output(cmd, shell=True)
    """
    findings = detect_docker_exec(_exec_agent(src))
    assert not any(f.id == "AG-DOCKER-EXEC" for f in findings)
