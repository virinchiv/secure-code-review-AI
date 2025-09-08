import json
import os

def save_report_json(report, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"✅ Saved JSON report to {filename}")

def save_report_markdown(report, filename="report.md"):
    with open(filename, "w") as f:
        f.write("# 🔒 Vulnerability Report\n\n")
        for vuln in report:
            f.write(f"## 🧠 {vuln['type']} at line {vuln['line']}\n")
            f.write(f"**Code:**\n```python\n{vuln['code'].strip()}\n```\n\n")
            f.write(f"**Explanation:**\n{vuln['explanation']}\n\n")
    print(f"✅ Saved Markdown report to {filename}")
