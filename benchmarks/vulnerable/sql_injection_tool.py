"""Vulnerable fixture: SQL injection via tool parameter.
Expected: AG-SQL fires on sql_engine function.
Pattern: smolagents text_to_sql example — exact real-world case.
"""
from langchain.agents import tool
import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")


@tool
def sql_engine(query: str) -> str:
    """Execute a SQL query against the users database.

    Useful for looking up user information.
    """
    # VULNERABLE: raw parameter to SQL execution
    rows = conn.execute(query).fetchall()
    return str(rows)
