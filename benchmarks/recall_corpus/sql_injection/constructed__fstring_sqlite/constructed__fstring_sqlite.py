# CONSTRUCTED recall case — NOT third-party code. Author-written to model a
# documented vuln class. Class: SQL injection (CWE-89).
# Reference pattern: identical shape to the real smolagents text_to_sql and
# CAMEL SQLToolkit cases in this corpus — an agent tool that concatenates an
# LLM/attacker-controlled string straight into cursor.execute().
import sqlite3


def query_customers(filter_expr: str) -> list:
    """Search the customer table. Use this to answer questions about customers."""
    conn = sqlite3.connect("customers.db")
    cursor = conn.cursor()
    # VULNERABLE: attacker-controlled filter_expr concatenated into SQL.
    cursor.execute(f"SELECT * FROM customers WHERE {filter_expr}")
    return cursor.fetchall()
