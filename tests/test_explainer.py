import ast
from backend.services.scanner import run_static_analysis
from backend.services.explainer import explain_vulnerabilities
from backend.services.report_generator import save_report_json, save_report_markdown

with open("data/sql_injection.py", "r") as f:
    code = f.read()

tree = ast.parse(code)

scanner_output = run_static_analysis(tree, code)

print("Vulnerabilities detected:")
for vuln in scanner_output:
    print(f"- {vuln['type']} at line {vuln['line']}: {vuln['code']}")

if scanner_output:
    print("\nAttempting to get explanations...")
    llm_output = explain_vulnerabilities(scanner_output)
    print(llm_output)
    save_report_json(llm_output)
    save_report_markdown(llm_output)
else:
    print("No vulnerabilities detected.")
