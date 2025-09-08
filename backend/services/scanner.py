import ast
from ..utils.security_rules import (
    detect_sql_injection,
    detect_xss,
    detect_hardcoded_secrets,
    detect_dangerous_calls,
    detect_insecure_randomness,
    detect_insecure_deserialization,
)

def run_static_analysis(tree, code):
    code_lines = code.splitlines()
    vulnerabilities = []

    for node in ast.walk(tree):
        if detect_sql_injection(node):
            vulnerabilities.append({
                "type": "SQL Injection",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
        if detect_xss(node):
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
        if detect_hardcoded_secrets(node):
            vulnerabilities.append({
                "type": "Hardcoded Secret",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
        if detect_dangerous_calls(node):
            vulnerabilities.append({
                "type": "Command Injection",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
        if detect_insecure_randomness(node):
            vulnerabilities.append({
                "type": "Insecure Randomness",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
        if detect_insecure_deserialization(node):
            vulnerabilities.append({
                "type": "Insecure Deserialization",
                "line": getattr(node, 'lineno', -1),
                "code": code_lines[node.lineno - 1]
            })
    return vulnerabilities
