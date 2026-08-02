"""Intraprocedural Control-Flow Graph (CFG) from stdlib ast.

Blueprint §4.1: the pipeline is `source → AST → CFG → call graph → taint`.
PyCG (call graph) is blocked on Python 3.12. The CFG layer is not.

This module builds a real CFG (basic blocks connected by control-flow edges)
from a Python function's AST using only stdlib. It enables:
  - Flow-sensitive taint analysis (the existing worklist runs over statements
    in any order; a CFG respects control flow)
  - Dominance analysis (for choke-point detection in the AIFG)
  - Dead-code detection

Approach: simplified Scalpel-style CFG — basic blocks from linear sequences
of statements; edges from if/for/while/try/with/return/break/continue.

Scope: single-function, intraproccedural. No inter-function edges.
Accuracy: handles the common patterns (if/else, for/while, try/except,
with-statements, early returns). Does NOT handle generators, async/await
comprehensions, or dynamic control flow — these produce conservative edges.

Pure stdlib only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Iterator


# ---------------------------------------------------------------------------
# 1. Basic blocks and edges
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    """A maximal sequence of statements with no internal branches."""
    block_id: int
    stmts:    list[ast.stmt] = field(default_factory=list)

    def __repr__(self) -> str:
        lines = [f"BB{self.block_id}"]
        for s in self.stmts[:3]:
            lines.append(f"  {ast.dump(s)[:60]}")
        if len(self.stmts) > 3:
            lines.append(f"  ... ({len(self.stmts)} stmts)")
        return "\n".join(lines)


@dataclass
class CFG:
    """Intraprocedural control-flow graph."""
    func_name: str
    blocks:    dict[int, BasicBlock] = field(default_factory=dict)
    edges:     list[tuple[int, int]] = field(default_factory=list)   # (from, to)
    entry_id:  int = 0
    exit_id:   int = -1    # virtual exit block

    def preds(self, block_id: int) -> list[int]:
        return [s for s, d in self.edges if d == block_id]

    def succs(self, block_id: int) -> list[int]:
        return [d for s, d in self.edges if s == block_id]

    def all_stmts(self) -> Iterator[ast.stmt]:
        """Yield all statements in topological order (BFS from entry)."""
        seen: set[int] = set()
        queue = [self.entry_id]
        while queue:
            bid = queue.pop(0)
            if bid in seen or bid not in self.blocks:
                continue
            seen.add(bid)
            yield from self.blocks[bid].stmts
            queue.extend(self.succs(bid))

    def to_dict(self) -> dict:
        return {
            "func": self.func_name,
            "entry": self.entry_id,
            "blocks": {bid: len(b.stmts) for bid, b in self.blocks.items()},
            "edges": self.edges,
        }


# ---------------------------------------------------------------------------
# 2. CFG builder
# ---------------------------------------------------------------------------

class CFGBuilder:
    """Build a CFG from a function definition node."""

    def __init__(self):
        self._next_id = 0
        self._cfg: CFG | None = None

    def _new_block(self) -> BasicBlock:
        bid = self._next_id
        self._next_id += 1
        bb = BasicBlock(block_id=bid)
        assert self._cfg is not None
        self._cfg.blocks[bid] = bb
        return bb

    def _add_edge(self, src: int, dst: int) -> None:
        assert self._cfg is not None
        if (src, dst) not in self._cfg.edges:
            self._cfg.edges.append((src, dst))

    def build(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
        self._next_id = 0
        self._cfg = CFG(func_name=func_node.name)

        entry  = self._new_block()          # BB0: entry
        exit_b = self._new_block()          # BB1: virtual exit
        self._cfg.entry_id = entry.block_id
        self._cfg.exit_id  = exit_b.block_id

        self._process_stmts(func_node.body, entry.block_id, exit_b.block_id)
        return self._cfg

    def _process_stmts(self, stmts: list[ast.stmt],
                        current_id: int,
                        exit_id: int,
                        break_target: int | None = None,
                        continue_target: int | None = None) -> int:
        """Process a list of statements, returning the final block id."""
        assert self._cfg is not None
        cur = current_id
        for stmt in stmts:
            cur = self._process_stmt(stmt, cur, exit_id,
                                     break_target, continue_target)
        return cur

    def _process_stmt(self, stmt: ast.stmt,
                       current_id: int, exit_id: int,
                       break_target: int | None,
                       continue_target: int | None) -> int:
        assert self._cfg is not None
        blocks = self._cfg.blocks

        # ------ simple statements: append to current block ------
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign,
                              ast.Expr, ast.Return, ast.Raise,
                              ast.Assert, ast.Delete, ast.Pass,
                              ast.Import, ast.ImportFrom,
                              ast.Global, ast.Nonlocal)):
            blocks[current_id].stmts.append(stmt)
            if isinstance(stmt, ast.Return):
                self._add_edge(current_id, exit_id)
                # Statements after return are unreachable; start a new dead block
                dead = self._new_block()
                return dead.block_id
            return current_id

        # ------ if / elif / else ------
        elif isinstance(stmt, ast.If):
            blocks[current_id].stmts.append(stmt)  # condition in current block
            merge = self._new_block()

            # then-branch
            then_start = self._new_block()
            self._add_edge(current_id, then_start.block_id)
            then_end = self._process_stmts(stmt.body, then_start.block_id, exit_id,
                                           break_target, continue_target)
            self._add_edge(then_end, merge.block_id)

            # else-branch (or fall-through)
            if stmt.orelse:
                else_start = self._new_block()
                self._add_edge(current_id, else_start.block_id)
                else_end = self._process_stmts(stmt.orelse, else_start.block_id, exit_id,
                                               break_target, continue_target)
                self._add_edge(else_end, merge.block_id)
            else:
                self._add_edge(current_id, merge.block_id)

            return merge.block_id

        # ------ for / while loops ------
        elif isinstance(stmt, (ast.For, ast.While)):
            header = self._new_block()   # loop header (condition check)
            self._add_edge(current_id, header.block_id)
            body_start = self._new_block()
            after_loop = self._new_block()

            self._add_edge(header.block_id, body_start.block_id)   # enter loop
            self._add_edge(header.block_id, after_loop.block_id)   # skip loop

            body_end = self._process_stmts(
                stmt.body, body_start.block_id, exit_id,
                break_target=after_loop.block_id,
                continue_target=header.block_id,
            )
            self._add_edge(body_end, header.block_id)  # loop back

            if stmt.orelse:
                else_start = self._new_block()
                self._add_edge(header.block_id, else_start.block_id)
                else_end = self._process_stmts(stmt.orelse, else_start.block_id,
                                               exit_id, break_target, continue_target)
                self._add_edge(else_end, after_loop.block_id)

            return after_loop.block_id

        # ------ break / continue ------
        elif isinstance(stmt, ast.Break):
            blocks[current_id].stmts.append(stmt)
            if break_target is not None:
                self._add_edge(current_id, break_target)
            dead = self._new_block()
            return dead.block_id

        elif isinstance(stmt, ast.Continue):
            blocks[current_id].stmts.append(stmt)
            if continue_target is not None:
                self._add_edge(current_id, continue_target)
            dead = self._new_block()
            return dead.block_id

        # ------ try / except / finally ------
        elif isinstance(stmt, ast.Try):
            blocks[current_id].stmts.append(stmt)
            merge = self._new_block()

            # try body
            try_start = self._new_block()
            self._add_edge(current_id, try_start.block_id)
            try_end = self._process_stmts(stmt.body, try_start.block_id, exit_id,
                                          break_target, continue_target)
            self._add_edge(try_end, merge.block_id)

            # except handlers (conservative: each handler can follow the try)
            for handler in stmt.handlers:
                h_start = self._new_block()
                self._add_edge(current_id, h_start.block_id)  # exception path
                h_end = self._process_stmts(handler.body, h_start.block_id, exit_id,
                                            break_target, continue_target)
                self._add_edge(h_end, merge.block_id)

            # else and finally
            if stmt.orelse:
                else_start = self._new_block()
                self._add_edge(try_end, else_start.block_id)
                else_end = self._process_stmts(stmt.orelse, else_start.block_id,
                                               exit_id, break_target, continue_target)
                self._add_edge(else_end, merge.block_id)
            if stmt.finalbody:
                fin_start = self._new_block()
                self._add_edge(merge.block_id, fin_start.block_id)
                merge = self._new_block()
                fin_end = self._process_stmts(stmt.finalbody, fin_start.block_id,
                                              exit_id, break_target, continue_target)
                self._add_edge(fin_end, merge.block_id)

            return merge.block_id

        # ------ with statement ------
        elif isinstance(stmt, ast.With):
            blocks[current_id].stmts.append(stmt)
            with_start = self._new_block()
            self._add_edge(current_id, with_start.block_id)
            with_end = self._process_stmts(stmt.body, with_start.block_id, exit_id,
                                           break_target, continue_target)
            return with_end

        # ------ fallback: add to current block ------
        else:
            blocks[current_id].stmts.append(stmt)
            return current_id


def build_cfg(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
    """Build a CFG for a function node. Convenience wrapper."""
    return CFGBuilder().build(func_node)


def build_cfgs_from_source(source: str) -> dict[str, CFG]:
    """Parse a Python source string and build CFGs for all top-level functions."""
    tree = ast.parse(source)
    cfgs: dict[str, CFG] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cfgs[node.name] = build_cfg(node)
    return cfgs
