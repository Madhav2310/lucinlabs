import base64
import binascii
import re

import bashlex
from bashlex.errors import ParsingError

from lucin.models import SkillCapability


class ShellCapabilityVisitor(bashlex.ast.nodevisitor):
    def __init__(self):
        self.capabilities = set()

    def visitcommand(self, n, parts):
        if not parts:
            return

        # In a CommandNode, parts can be WordNode, redirect, etc.
        # Find the first WordNode which is usually the command executable
        cmd_node = None
        for part in parts:
            if getattr(part, 'kind', None) == 'word':
                cmd_node = part
                break

        if not cmd_node:
            return

        cmd = cmd_node.word
        args = [p.word for p in parts if getattr(p, 'kind', None) == 'word' and p != cmd_node]

        # REMOTE_FETCH
        if cmd in ('curl', 'wget', 'nc', 'ftp'):
            self.capabilities.add(SkillCapability.REMOTE_FETCH)
            # Check for output redirection or -o/-O in args
            if any(arg in ('-o', '-O', '--output') for arg in args):
                self.capabilities.add(SkillCapability.FILESYSTEM_WRITE)
            # Also check for > or >> in redirect nodes
            if any(getattr(p, 'kind', None) == 'redirect' and p.type in ('>', '>>') for p in parts):
                self.capabilities.add(SkillCapability.FILESYSTEM_WRITE)

            # EGRESS via curl
            if cmd == 'curl':
                if any(arg in ('-d', '--data', '--data-binary', '--data-urlencode') for arg in args):
                    self.capabilities.add(SkillCapability.EGRESS)

        # DECODE
        elif cmd in ('base64', 'xxd', 'openssl', 'rot13', 'uudecode'):
            if any(arg in ('-d', '--decode', '-r', '-reverse') for arg in args):
                self.capabilities.add(SkillCapability.DECODE)

        # EXEC
        elif cmd in ('eval', 'source', 'exec'):
            self.capabilities.add(SkillCapability.EXEC)

        # EGRESS via other means
        elif cmd == 'mail':
            self.capabilities.add(SkillCapability.EGRESS)
        elif cmd == 'git':
            if args and args[0] == 'push':
                self.capabilities.add(SkillCapability.EGRESS)

        # CREDENTIAL_READ
        elif cmd in ('cat', 'grep', 'awk'):
            if any(any(x in arg for x in ('.ssh/', '.aws/', '.env', 'keychain')) for arg in args):
                self.capabilities.add(SkillCapability.CREDENTIAL_READ)

    def visitpipeline(self, n, parts):
        # Look for piping to interpreters
        if len(parts) > 1:
            last_cmd = parts[-1]
            if getattr(last_cmd, 'kind', None) == 'command':
                cmd_parts = last_cmd.parts
                for p in cmd_parts:
                    if getattr(p, 'kind', None) == 'word':
                        cmd = p.word
                        if cmd in ('sh', 'bash', 'zsh', 'python', 'python3', 'node', 'ruby', 'perl'):
                            self.capabilities.add(SkillCapability.EXEC)
                        break
        # Visit all children
        for part in parts:
            self.visit(part)

    def visitcommandsubstitution(self, n, command):
        self.capabilities.add(SkillCapability.EXEC)


def deobfuscate(text: str) -> str:
    """
    Attempt to find and decode base64/hex strings in the script.
    Appends any decodable ASCII payload to the script so bashlex can parse it.
    """
    decoded = text

    # Base64 heuristic
    b64_matches = set(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text))
    for match in b64_matches:
        try:
            # Add padding if needed
            padded = match + "=" * ((4 - len(match) % 4) % 4)
            dec = base64.b64decode(padded).decode('utf-8')
            # If it looks like valid ASCII/shell text, append it
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in dec):
                decoded += f"\n\n# DEOBFUSCATED:\n{dec}\n"
        except Exception:
            pass

    # Hex heuristic
    hex_matches = set(re.findall(r'(?:[0-9a-fA-F]{2}){10,}', text))
    for match in hex_matches:
        try:
            dec = binascii.unhexlify(match).decode('utf-8')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in dec):
                decoded += f"\n\n# DEOBFUSCATED:\n{dec}\n"
        except Exception:
            pass

    return decoded


def inspect_shell_script(script_text: str) -> list[SkillCapability]:
    """
    Semantic capability extractor for bash/sh scripts.
    Uses bashlex to parse the AST and avoid regex false positives.
    """
    capabilities = set()
    script_text = deobfuscate(script_text)

    try:
        parts = bashlex.parse(script_text)
        visitor = ShellCapabilityVisitor()
        for part in parts:
            visitor.visit(part)
        capabilities.update(visitor.capabilities)
    except (ParsingError, Exception):
        # Fallback to regex if parsing completely fails (e.g. bashlex internal bug on comments)

        # Strip comments to avoid matching prose in the regex fallback
        lines = [line.split('#')[0] for line in script_text.split('\n')]
        clean_text = " ".join(lines)

        if re.search(r'\b(curl|wget)\b', clean_text):
            capabilities.add(SkillCapability.REMOTE_FETCH)
        if re.search(r'\|\s*(sh|bash|python|node)\b', clean_text):
            capabilities.add(SkillCapability.EXEC)

    # Substring fallback for credential_read which might not be cleanly parsed
    # Also use clean_text to avoid triggering on comments
    lines = [line.split('#')[0] for line in script_text.split('\n')]
    clean_text = " ".join(lines)
    if re.search(r'(\.ssh/|\.aws/|\.env|\bkeychain\b)', clean_text):
        capabilities.add(SkillCapability.CREDENTIAL_READ)

    return list(capabilities)


# Fenced shell code blocks in Markdown prose (SKILL.md, references/*.md).
_MD_SHELL_FENCE = re.compile(r"```(?:bash|sh|shell|zsh|console)?\n(.*?)```", re.DOTALL)


def extract_shell_blocks_from_markdown(text: str) -> list[str]:
    """Extract fenced shell code blocks from Markdown prose.

    Modeled on Cisco's skill-scanner (github.com/cisco-ai-defense/skill-scanner,
    Apache-2.0, core/analyzers/pipeline_analyzer.py), which treats SKILL.md
    prose as inspectable, executable-intent content: an instruction telling the
    agent to run `curl ... | sh` is just as real a chain as a bundled script
    doing the same thing. Before this, Lucin only inspected `scripts/*.sh` —
    a shell pipeline embedded directly in the markdown body was invisible.
    """
    return [m.group(1) for m in _MD_SHELL_FENCE.finditer(text)]
