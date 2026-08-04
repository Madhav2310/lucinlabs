"""Parser for skill directories and instruction files."""

import os
from pathlib import Path

import yaml

from lucin._fs import iter_files
from lucin.models import Agent, InstructionBlock, Skill, SkillCapability, Tool
from lucin.parsers.shell_inspector import extract_shell_blocks_from_markdown, inspect_shell_script

# A scanner that reads attacker-controlled paths off the host is the failure
# class it exists to catch in others (path traversal, symlink escape). These
# caps are deliberately conservative — a legitimate skill has no reason to
# reference a multi-megabyte file from SKILL.md prose or a script.
MAX_FILE_BYTES = 2 * 1024 * 1024       # 2 MB per referenced/scripted file
MAX_BUNDLE_BYTES = 50 * 1024 * 1024    # 50 MB total read per skill


def _safe_resolve(root: Path, candidate: Path, skill: "Skill") -> Path | None:
    """Resolve `candidate` and return it only if it stays within `root`.

    Rejects symlink escapes (`scripts/ -> /etc`) and `../` traversal alike,
    since both collapse to the same check once both sides are resolved.
    Rejections are recorded on `skill.diagnostics`, never silently dropped.
    """
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        skill.diagnostics.append(f"skipped (unresolvable path): {candidate}")
        return None
    if resolved != root and root not in resolved.parents:
        skill.diagnostics.append(
            f"skipped (escapes skill root {root}): {candidate} -> {resolved}"
        )
        return None
    return resolved


def _safe_read_text(path: Path, skill: "Skill", *, budget: list[int]) -> str | None:
    """Read `path` as text, enforcing the per-file and per-bundle size caps.

    `budget` is a single-element list used as a mutable running total across
    every call for one skill (Python has no nonlocal-by-reference for ints).
    """
    try:
        size = path.stat().st_size
    except OSError:
        skill.diagnostics.append(f"skipped (stat failed): {path}")
        return None
    if size > MAX_FILE_BYTES:
        skill.diagnostics.append(
            f"skipped (file {size}B exceeds {MAX_FILE_BYTES}B cap): {path}"
        )
        return None
    if budget[0] + size > MAX_BUNDLE_BYTES:
        skill.diagnostics.append(
            f"skipped (bundle size cap {MAX_BUNDLE_BYTES}B reached): {path}"
        )
        return None
    budget[0] += size
    return path.read_text(errors="ignore")

def _extract_python_capabilities(source: str) -> list[SkillCapability]:
    """Robust extractor for Python scripts to find SkillCapabilities using AST."""
    import ast
    caps = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Fallback to regex if syntax error (e.g., incomplete script)
        import re
        if re.search(r'\b(subprocess|os\.system|eval|exec|os\.popen)\b', source): caps.add(SkillCapability.EXEC)
        if re.search(r'\b(requests|urllib|aiohttp|httpx)\b', source):
            caps.add(SkillCapability.REMOTE_FETCH)
            caps.add(SkillCapability.EGRESS)
        if re.search(r'\b(pickle|yaml|marshal)\b', source): caps.add(SkillCapability.DESERIALIZE)
        return list(caps)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split('.')[0]
                if name in ["subprocess", "os", "sh", "pty"]: caps.add(SkillCapability.EXEC)
                if name in ["requests", "urllib", "aiohttp", "httpx"]:
                    caps.add(SkillCapability.REMOTE_FETCH)
                    caps.add(SkillCapability.EGRESS)
                if name in ["pickle", "yaml", "marshal"]: caps.add(SkillCapability.DESERIALIZE)
                if name in ["base64", "codecs"]: caps.add(SkillCapability.DECODE)
                if name in ["dotenv"]: caps.add(SkillCapability.CREDENTIAL_READ)
                if name in ["pathlib", "shutil"]: caps.add(SkillCapability.FILESYSTEM_WRITE)
        elif isinstance(node, ast.ImportFrom):
            name = node.module.split('.')[0] if node.module else ""
            if name in ["subprocess", "os", "sh", "pty"]: caps.add(SkillCapability.EXEC)
            if name in ["requests", "urllib", "aiohttp", "httpx"]:
                caps.add(SkillCapability.REMOTE_FETCH)
                caps.add(SkillCapability.EGRESS)
            if name in ["pickle", "yaml", "marshal"]: caps.add(SkillCapability.DESERIALIZE)
            if name in ["base64", "codecs"]: caps.add(SkillCapability.DECODE)
            if name in ["dotenv"]: caps.add(SkillCapability.CREDENTIAL_READ)
            if name in ["pathlib", "shutil"]: caps.add(SkillCapability.FILESYSTEM_WRITE)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ["eval", "exec"]: caps.add(SkillCapability.EXEC)
                if node.func.id == "open": caps.add(SkillCapability.FILESYSTEM_WRITE)
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                caps.add(SkillCapability.CREDENTIAL_READ)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if ".env" in node.value:
                caps.add(SkillCapability.CREDENTIAL_READ)
            if "aws/credentials" in node.value:
                caps.add(SkillCapability.CREDENTIAL_READ)

    # In older python versions (<=3.7), ast.Constant is ast.Str
    for node in ast.walk(tree):
        if hasattr(ast, "Str") and isinstance(node, getattr(ast, "Str")):
            if ".env" in node.s or "aws/credentials" in node.s:
                caps.add(SkillCapability.CREDENTIAL_READ)

    return list(caps)

def _extract_js_capabilities(source: str) -> list[SkillCapability]:
    """Robust extractor for Node.js/TS scripts to find SkillCapabilities using regex with word boundaries."""
    import re
    caps = set()

    # Strip comments to prevent false positives
    clean_src = re.sub(r'//.*', '', source)
    clean_src = re.sub(r'/\*.*?\*/', '', clean_src, flags=re.DOTALL)

    if re.search(r'\b(axios|fetch|https?)\b', clean_src):
        caps.add(SkillCapability.REMOTE_FETCH)
        caps.add(SkillCapability.EGRESS)
    if re.search(r'\b(atob|Buffer\.from|decode)\b', clean_src):
        caps.add(SkillCapability.DECODE)
    if re.search(r'\b(yaml\.load|yaml\.parse)\b', clean_src):
        caps.add(SkillCapability.DESERIALIZE)
    if re.search(r'\b(exec|execSync|spawn|shelljs)\b', clean_src):
        caps.add(SkillCapability.EXEC)
    if re.search(r'\b(process\.env|dotenv)\b', clean_src):
        caps.add(SkillCapability.CREDENTIAL_READ)
    if re.search(r'\b(fs|fs-extra|path)\b', clean_src):
        caps.add(SkillCapability.FILESYSTEM_WRITE)

    return list(caps)

def parse_skill(target: Path) -> list[Agent]:
    """Parse a skill directory.

    A directory is considered a skill if it contains a SKILL.md or a scripts/ directory.
    Every path this function reads is checked against the resolved skill root
    before being opened — a symlink or `../` reference pointing outside the
    skill directory is rejected and recorded in `skill.diagnostics`, not read.
    """
    if not target.is_dir():
        return []

    try:
        root = target.resolve(strict=True)
    except OSError:
        return []

    skill_md = target / "SKILL.md"
    if not skill_md.exists():
        skill_md = target / "skill.md"

    scripts_dir = target / "scripts"

    if not skill_md.exists() and not scripts_dir.exists():
        return []

    skill_name = target.name
    skill = Skill(
        name=skill_name,
        source_file=str(skill_md) if skill_md.exists() else str(target)
    )
    budget = [0]  # running total of bytes read, shared across every helper below

    if skill_md.exists():
        resolved_md = _safe_resolve(root, skill_md, skill)
        if resolved_md is not None:
            _parse_markdown_frontmatter(resolved_md, skill, budget)
            _extract_instruction_blocks(resolved_md, skill, budget)

    ref_dir = target / "references"
    resolved_ref_dir = _safe_resolve(root, ref_dir, skill) if ref_dir.exists() else None
    if resolved_ref_dir is not None and resolved_ref_dir.is_dir():
        # Iterate md files up to depth 1 (spec: "keep file references one
        # level deep"; deeper following is a separate, bounded piece of work).
        for item in resolved_ref_dir.iterdir():
            if item.is_file() and item.suffix.lower() == ".md":
                resolved_item = _safe_resolve(root, item, skill)
                if resolved_item is not None:
                    _extract_instruction_blocks(resolved_item, skill, budget)

    resolved_scripts_dir = _safe_resolve(root, scripts_dir, skill) if scripts_dir.exists() else None
    if resolved_scripts_dir is not None and resolved_scripts_dir.is_dir():
        for item in iter_files(resolved_scripts_dir, "*"):
            if item.is_file():
                resolved_item = _safe_resolve(root, item, skill)
                if resolved_item is not None:
                    _parse_script_tool(resolved_item, skill, budget)

    _parse_dependencies(target, skill)

    agent = Agent(
        name=skill_name,
        framework="skill",
        source_file=skill.source_file,
        tools=skill.scripts,
        skill=skill,
        posture_findings_apply=False  # MUST set posture_findings_apply=False (landmine #3)
    )
    return [agent]

def _parse_dependencies(target: Path, skill: Skill):
    req_txt = target / "requirements.txt"
    if req_txt.exists():
        try:
            from packaging.requirements import Requirement
            content = req_txt.read_text(errors='ignore')
            for line in content.split('\n'):
                line = line.strip().split('#')[0]
                if line:
                    try:
                        req = Requirement(line)
                        skill.dependencies.append(req.name.lower())
                    except Exception:
                        # Fallback for malformed lines
                        import re
                        pkg_name = re.split(r'[=<>~]', line)[0].strip().lower()
                        if pkg_name:
                            skill.dependencies.append(pkg_name)
        except ImportError:
            # Fallback if packaging isn't available
            content = req_txt.read_text(errors='ignore')
            for line in content.split('\n'):
                line = line.strip().split('#')[0]
                if line:
                    import re
                    pkg_name = re.split(r'[=<>~]', line)[0].strip().lower()
                    if pkg_name:
                        skill.dependencies.append(pkg_name)
        except Exception:
            pass

    pkg_json = target / "package.json"
    if pkg_json.exists():
        try:
            import json
            data = json.loads(pkg_json.read_text(errors='ignore'))
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            for pkg in deps:
                skill.dependencies.append(pkg.lower())
            for pkg in dev_deps:
                skill.dependencies.append(pkg.lower())
        except Exception:
            pass

def _parse_allowed_tools(value) -> list[str]:
    """Tokenize `allowed-tools` per the Agent Skills spec.

    The spec defines this as a *space-separated string*
    (`allowed-tools: Bash(git:*) Bash(jq:*) Read`), not a YAML list. Splitting
    a string naively on whitespace would break scoped syntax like
    `Bash(git:*)` into fragments, so tokens are grouped by paren-depth: a
    space only ends a token at depth 0. A YAML-list form is also accepted for
    authors who write it that way in practice, even though it isn't spec.
    """
    if isinstance(value, list):
        return [str(v).lower() for v in value]
    if not isinstance(value, str):
        return []
    tokens: list[str] = []
    current = ""
    depth = 0
    for ch in value:
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth = max(0, depth - 1)
            current += ch
        elif ch.isspace() and depth == 0:
            if current:
                tokens.append(current)
                current = ""
        else:
            current += ch
    if current:
        tokens.append(current)
    return [t.lower() for t in tokens]


def _parse_markdown_frontmatter(file_path: Path, skill: Skill, budget: list[int]):
    content = _safe_read_text(file_path, skill, budget=budget)
    if content is None:
        return
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            try:
                fm = yaml.safe_load(parts[1]) or {}
                skill.frontmatter = fm
                if "allowed-tools" in fm:
                    skill.declared_capabilities.extend(_parse_allowed_tools(fm["allowed-tools"]))
            except Exception:
                pass

def _extract_instruction_blocks(file_path: Path, skill: Skill, budget: list[int]):
    content = _safe_read_text(file_path, skill, budget=budget)
    if content is None:
        return
    skill.instructions.append(
        InstructionBlock(
            text=content,
            source_file=str(file_path),
            line_start=1,
            line_end=content.count("\n") + 1
        )
    )
    # A shell pipeline embedded directly in the prose (e.g. "run `curl ... | sh`")
    # is just as real a chain as the same pipeline in a bundled scripts/*.sh file
    # — see shell_inspector.extract_shell_blocks_from_markdown's docstring.
    for block in extract_shell_blocks_from_markdown(content):
        skill.observed_capabilities.extend(inspect_shell_script(block))

def _parse_script_tool(file_path: Path, skill: Skill, budget: list[int]):
    content = _safe_read_text(file_path, skill, budget=budget)
    if content is None:
        return
    tool = Tool(
        name=file_path.name,
        description="Skill script",  # Intentionally not the markdown body (landmine #1)
        source_file=str(file_path),
        capabilities=[]
    )

    if file_path.suffix in ('.sh', '.bash'):
        caps = inspect_shell_script(content)
        skill.observed_capabilities.extend(caps)
    elif file_path.suffix == '.py':
        caps = _extract_python_capabilities(content)
        skill.observed_capabilities.extend(caps)
    elif file_path.suffix in ('.js', '.ts', '.cjs', '.mjs'):
        caps = _extract_js_capabilities(content)
        skill.observed_capabilities.extend(caps)

    skill.scripts.append(tool)
