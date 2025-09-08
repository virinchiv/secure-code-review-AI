import ast
import re
import os

def detect_sql_injection(node) -> bool:
    """Detect SQL injection vulnerabilities in AST nodes"""
    # Check for direct execute calls with binary operations
    if isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr == "execute":
        for arg in node.args:
            if isinstance(arg, ast.BinOp):
                return True
            if isinstance(arg, ast.JoinedStr):
                return True
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    return True
    
    # Check for assignments that create SQL queries with string concatenation
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in ['query', 'sql', 'stmt']:
                if isinstance(node.value, ast.BinOp):
                    return True
                if isinstance(node.value, ast.JoinedStr):
                    return True
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "format":
                        return True
    return False


SECRET_KEYWORDS = {"password", "passwd", "pwd", "secret", "api_key", "apikey", "token", "access_key"}
KEY_PATTERNS = [
    r"sk-[a-zA-Z0-9]{16,}",                  # OpenAI API keys or similar
    r"AKIA[0-9A-Z]{16}",                     # AWS access key
    r"ghp_[A-Za-z0-9]{36}",                  # GitHub personal access token
    r"[A-Za-z0-9]{32,}",                     # Generic long token
]

def detect_hardcoded_secrets(node):
    """
    Detects hardcoded credentials and secrets in variable assignments.
    """
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(key in var_name for key in SECRET_KEYWORDS):
                    if isinstance(node.value, (ast.Str, ast.Constant)) and isinstance(node.value.value, str):
                        return True
                if isinstance(node.value, (ast.Str, ast.Constant)) and isinstance(node.value.value, str):
                    val = node.value.value
                    for pattern in KEY_PATTERNS:
                        if re.fullmatch(pattern, val):
                            return True
    return False

DANGEROUS_FUNCTIONS = [
    ("os", "system"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("os", "popen")
]
def is_dangerous_call(func):
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = func.value.id
        function = func.attr
        return (module, function) in DANGEROUS_FUNCTIONS
    return False

def detect_dangerous_calls(node):
    if isinstance(node, ast.Call):
        if is_dangerous_call(node.func):
            for arg in node.args:
                if isinstance(arg, ast.BinOp) or isinstance(arg, ast.Name):
                    return True
    return False

# XSS detection
def is_flask_template_render(func):
    return isinstance(func, ast.Name) and func.id == "render_template_string"

def is_user_input(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            if node.func.value.id == "request":
                return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
        return True
    return False

def detect_xss(node):
    """
    Detects XSS via unsafe rendering in render_template_string.
    """
    if isinstance(node, ast.Call) and is_flask_template_render(node.func):
        for arg in node.args:
            if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr):
                # Check if user input is part of the string
                if contains_user_input(arg):
                    return True
    return False

def contains_user_input(expr):
    if isinstance(expr, ast.BinOp):
        return contains_user_input(expr.left) or contains_user_input(expr.right)
    if isinstance(expr, ast.Call):
        return is_user_input(expr)
    if isinstance(expr, ast.Name):
        return True
    return False

RISKY_RANDOM_FUNCTIONS = {
    "random", "randint", "choice", "choices", "randrange", "shuffle", "uniform"
}
def is_insecure_random_call(node):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "random" and node.func.attr in RISKY_RANDOM_FUNCTIONS:
                    return True
    return False

def detect_insecure_randomness(node):
    """
    Detects use of insecure randomness for token/secret generation.
    """
    if isinstance(node, ast.Assign):
        for value in ast.walk(node.value):
            if is_insecure_random_call(value):
                return True
    return False

DANGEROUS_DESERIALIZATION_FUNCTIONS = {
    ("pickle", "load"),
    ("pickle", "loads"),
    ("yaml", "load"),
    ("marshal", "load"),
    ("", "eval"),  # Built-in
}

def detect_insecure_deserialization(node):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            return True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module_name = node.func.value.id
            func_name = node.func.attr
            if (module_name, func_name) in DANGEROUS_DESERIALIZATION_FUNCTIONS:
                return True
    return False