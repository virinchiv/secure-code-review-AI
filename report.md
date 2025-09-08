# 🔒 Vulnerability Report

## 🧠 SQL Injection at line 5
**Code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Explanation:**
**Explanation:**  
This code is vulnerable to **SQL Injection** because it directly inserts user input (`username` and `password`) into the SQL query string. An attacker can manipulate these inputs to alter the query and gain unauthorized access or damage the database.

**Secure Approach (using parameterized queries):**

**Python (with sqlite3):**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```

**Why this is secure:**  
Parameterized queries ensure that user inputs are treated as data, not as part of the SQL command, preventing attackers from injecting malicious SQL code.

