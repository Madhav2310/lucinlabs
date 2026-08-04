"""Regression test for a real infinite-loop bug in `source_sink_taint`.

Found scanning the 337-skill corpus: when a variable is assigned from two
different fixed sources in different branches (e.g. an if/else — one branch
reads an env var, the other reads stdin), the fixpoint loop used to
overwrite the variable's attributed source every round, flip-flopping
forever and never converging. 17 of 3,229 real corpus `.py` files hit this;
one (697 lines) ran `dict.keys()` calls 24M+ times before being killed.

This must complete near-instantly, not time out.
"""
import ast
import signal

import pytest

from lucin.parsers.body_inspector import source_sink_taint


def test_conditional_reassignment_does_not_hang():
    src = (
        "import os\n"
        "def get_user(use_env):\n"
        "    if use_env:\n"
        "        api_user = os.environ.get('USER')\n"
        "    else:\n"
        "        api_user = input('Enter user: ')\n"
        "    return api_user\n"
    )
    tree = ast.parse(src)

    def _handler(signum, frame):
        raise TimeoutError("source_sink_taint hung on a conditional-reassignment pattern")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(5)
    try:
        flows = source_sink_taint(tree)  # must not hang
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    assert flows == []  # no dangerous sink here — this is a pure hang/termination test
