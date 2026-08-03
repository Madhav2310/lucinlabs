"""Tests for the LlamaIndex BaseToolSpec class-method tool parser.

These lock in the parser-coverage recovery: LlamaIndex exposes tools as *methods*
on a BaseToolSpec subclass, declared via the `spec_functions` class attribute.
Before this parser those files parsed to ZERO agents, so no detector ever ran on
them. Precision guard: only methods with an explicit registration signal
(BaseToolSpec base + spec_functions / public methods) become tools — never
arbitrary class methods, and never dunder/private/constructor methods.
"""

import tempfile
from pathlib import Path

import pytest

from lucin.parsers import detect_and_parse
from lucin.parsers.llamaindex_parser import parse_llamaindex


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def _write(tmp_dir: Path, name: str, content: str) -> Path:
    p = tmp_dir / name
    p.write_text(content)
    return p


class TestSpecFunctions:
    def test_flat_spec_functions_list(self, tmp_dir):
        """The real llamaindex OpenAPIToolSpec shape: spec_functions = ["name"]."""
        _write(tmp_dir, "openapi.py", '''
from llama_index.core.tools.tool_spec.base import BaseToolSpec

class OpenAPIToolSpec(BaseToolSpec):
    spec_functions = ["load_openapi_spec"]

    def __init__(self, url=None):
        import requests
        self.spec = requests.get(url).text

    def load_openapi_spec(self):
        """Return the parsed OpenAPI spec."""
        return self.spec

    def _private_helper(self):
        return 1
''')
        agents = parse_llamaindex(tmp_dir)
        assert len(agents) == 1
        a = agents[0]
        assert a.framework == "llamaindex"
        assert a.name == "OpenAPIToolSpec"
        names = {t.name for t in a.tools}
        # Only the registered method is a tool — not __init__, not the private helper.
        assert names == {"load_openapi_spec"}

    def test_paired_sync_async_spec_functions(self, tmp_dir):
        """LlamaIndex also supports (sync, async) tuple entries — both are tools."""
        _write(tmp_dir, "ci.py", '''
from llama_index.core.tools.tool_spec.base import BaseToolSpec

class CodeInterpreterToolSpec(BaseToolSpec):
    spec_functions = [
        ("execute_code", "aexecute_code"),
        ("execute_command", "aexecute_command"),
    ]

    def execute_code(self, code: str):
        """Run code."""
        return exec(code)

    async def aexecute_code(self, code: str):
        return exec(code)

    def execute_command(self, cmd: str):
        import subprocess
        return subprocess.run(cmd, shell=True)

    async def aexecute_command(self, cmd: str):
        import subprocess
        return subprocess.run(cmd, shell=True)
''')
        agents = parse_llamaindex(tmp_dir)
        assert len(agents) == 1
        names = {t.name for t in agents[0].tools}
        assert names == {"execute_code", "aexecute_code",
                         "execute_command", "aexecute_command"}

    def test_no_spec_functions_falls_back_to_public_methods(self, tmp_dir):
        """No spec_functions => BaseToolSpec default: public methods only."""
        _write(tmp_dir, "salesforce.py", '''
from llama_index.core.tools.tool_spec.base import BaseToolSpec

class SalesforceToolSpec(BaseToolSpec):
    def __init__(self, **kw):
        self.sf = None

    def execute_soql(self, query: str):
        """Run a SOQL query."""
        return self.sf.query_all(query)

    def _resolve(self):
        return None
''')
        agents = parse_llamaindex(tmp_dir)
        assert len(agents) == 1
        names = {t.name for t in agents[0].tools}
        # public method exposed; __init__ and _resolve excluded
        assert names == {"execute_soql"}


class TestSoundness:
    def test_plain_class_not_a_toolspec_is_ignored(self, tmp_dir):
        """A class that does NOT subclass *ToolSpec must not be parsed as tools."""
        _write(tmp_dir, "plain.py", '''
from llama_index.core.bridge.pydantic import BaseModel

class CassandraDatabase:
    def run(self, query: str):
        return self._session.execute(query)
''')
        agents = parse_llamaindex(tmp_dir)
        assert agents == []

    def test_dotted_base_toolspec_recognized(self, tmp_dir):
        _write(tmp_dir, "dotted.py", '''
import llama_index.core.tools.tool_spec.base as base

class MyToolSpec(base.BaseToolSpec):
    spec_functions = ["do_thing"]

    def do_thing(self, x: str):
        """Do a thing."""
        return x
''')
        agents = parse_llamaindex(tmp_dir)
        assert len(agents) == 1
        assert {t.name for t in agents[0].tools} == {"do_thing"}


class TestIntegration:
    def test_end_to_end_produces_analyzable_agent(self, tmp_dir):
        """detect_and_parse must surface the ToolSpec agent (was zero agents before)."""
        _write(tmp_dir, "openapi.py", '''
from llama_index.core.tools.tool_spec.base import BaseToolSpec

class OpenAPIToolSpec(BaseToolSpec):
    spec_functions = ["load_openapi_spec"]

    def load_openapi_spec(self):
        """Return the parsed OpenAPI spec."""
        return None
''')
        agents = detect_and_parse(tmp_dir)
        llama = [a for a in agents if a.framework == "llamaindex"]
        assert len(llama) == 1
        assert llama[0].source_file  # source_file set => detectors will run on it
