# Security Code Review Guide

This guide provides a checklist and patterns for conducting security-focused code reviews.

## Security Review Mindset

When reviewing code for security:
1. **Assume inputs are malicious**: All user input, API responses, and file content
2. **Verify trust boundaries**: Check authentication/authorization at each boundary
3. **Follow data flow**: Track sensitive data from input to storage to output
4. **Question assumptions**: "What if this is null?", "What if this is 1GB?"
5. **Think like an attacker**: How would you exploit this?

---

## Quick Security Checklist

### Input Handling
- [ ] All user input is validated
- [ ] Input validation uses allowlists (not blocklists)
- [ ] File uploads are validated (type, size, content)
- [ ] Path traversal is prevented
- [ ] Query parameters are sanitized

### Authentication & Session
- [ ] Passwords are hashed with modern algorithms (Argon2, bcrypt)
- [ ] Session tokens are cryptographically random
- [ ] Session cookies have Secure, HttpOnly, SameSite flags
- [ ] Password reset tokens expire appropriately
- [ ] MFA is available for sensitive operations

### Authorization
- [ ] Every endpoint checks authorization
- [ ] Authorization checks are on the server-side
- [ ] Object-level authorization is enforced (no IDOR)
- [ ] Admin functions are properly protected
- [ ] Principle of least privilege is followed

### Data Protection
- [ ] Sensitive data is encrypted at rest
- [ ] Sensitive data is encrypted in transit (TLS)
- [ ] PII is handled according to policy
- [ ] Secrets are not hardcoded
- [ ] Logs don't contain sensitive data

### Error Handling
- [ ] Errors don't reveal sensitive information
- [ ] Stack traces are not exposed to users
- [ ] Failed operations fail securely
- [ ] Error messages are consistent (no enumeration)

### Dependencies
- [ ] Dependencies are from trusted sources
- [ ] Dependencies are pinned to specific versions
- [ ] No known vulnerabilities in dependencies
- [ ] Unused dependencies are removed

---

## OWASP Top 10 Review Points

### A01: Broken Access Control

**Look for**:
- Missing authorization checks on endpoints
- Client-side only authorization
- Direct object references (IDOR)
- Path traversal vulnerabilities
- CORS misconfiguration

**Red flags**:
```python
# Bad: No authorization check
@app.route('/user/<id>')
def get_user(id):
    return User.query.get(id)  # Anyone can access any user

# Good: Verify ownership
@app.route('/user/<id>')
@login_required
def get_user(id):
    user = User.query.get(id)
    if user.id != current_user.id:
        abort(403)
    return user
```

### A02: Cryptographic Failures

**Look for**:
- Weak hashing algorithms (MD5, SHA1 for passwords)
- Hardcoded encryption keys
- Missing encryption for sensitive data
- Weak random number generation
- Deprecated TLS versions

**Red flags**:
```python
# Bad: MD5 for passwords
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# Good: Use proper password hashing
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

### A03: Injection

**Look for**:
- SQL queries built with string concatenation
- Shell commands with user input
- LDAP queries with user input
- XPath/XML injection
- Template injection

**Red flags**:
```python
# Bad: SQL injection
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Good: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

```javascript
// Bad: Command injection
exec(`ls ${userInput}`);

// Good: Avoid shell, use safe APIs
fs.readdir(path.resolve(baseDir, userInput));
```

### A04: Insecure Design

**Look for**:
- Missing rate limiting
- No account lockout
- Missing CAPTCHA for sensitive operations
- Lack of defense in depth
- Trust boundaries not enforced

### A05: Security Misconfiguration

**Look for**:
- Default credentials
- Unnecessary features enabled
- Verbose error messages
- Missing security headers
- Outdated software

**Check for security headers**:
```
Content-Security-Policy
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security
```

### A06: Vulnerable Components

**Look for**:
- Outdated dependencies
- Dependencies with known CVEs
- Unused dependencies
- Unpinned versions

### A07: Authentication Failures

**Look for**:
- Weak password requirements
- Missing brute-force protection
- Session fixation
- Credentials in URLs
- Missing MFA option

**Red flags**:
```python
# Bad: Weak password validation
if len(password) >= 6:
    accept_password()

# Good: Strong password policy
from zxcvbn import zxcvbn
result = zxcvbn(password)
if result['score'] < 3:
    reject_password("Password too weak")
```

### A08: Software and Data Integrity Failures

**Look for**:
- Unsigned updates
- Unverified deserialization
- CI/CD pipeline vulnerabilities
- Missing integrity checks on downloads

**Red flags**:
```python
# Bad: Deserializing untrusted data
import pickle
data = pickle.loads(user_input)  # Remote code execution!

# Good: Use safe formats
import json
data = json.loads(user_input)
```

### A09: Security Logging and Monitoring Failures

**Look for**:
- Missing audit logs
- Logs with sensitive data
- No alerting on suspicious activity
- Insufficient log retention

**What to log**:
- Authentication events (success/failure)
- Authorization failures
- Input validation failures
- Application errors
- Admin actions

### A10: Server-Side Request Forgery (SSRF)

**Look for**:
- User-controlled URLs being fetched
- URL parsing issues
- Missing URL validation

**Red flags**:
```python
# Bad: SSRF vulnerability
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    return requests.get(url).text  # Can access internal services!

# Good: Validate URLs
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com']

def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(400, "URL not allowed")
    if parsed.scheme not in ['http', 'https']:
        abort(400, "Scheme not allowed")
    return requests.get(url).text
```

---

## Language-Specific Security Patterns

### JavaScript/TypeScript

```javascript
// XSS Prevention
// Bad: innerHTML with user content
element.innerHTML = userContent;

// Good: Use textContent or sanitize
element.textContent = userContent;
// Or use DOMPurify for HTML
element.innerHTML = DOMPurify.sanitize(userContent);

// Prototype Pollution Prevention
// Bad: Merging user input directly
Object.assign(config, userInput);

// Good: Use safe merge or validate keys
const safeKeys = ['name', 'email'];
for (const key of safeKeys) {
    if (key in userInput) config[key] = userInput[key];
}

// Path Traversal
// Bad
fs.readFile(path.join('/uploads', userFilename));

// Good
const safePath = path.resolve('/uploads', userFilename);
if (!safePath.startsWith('/uploads/')) {
    throw new Error('Invalid path');
}
```

### Python

```python
# SQL Injection
# Bad
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# Good
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# Command Injection
# Bad
os.system(f"convert {filename} output.png")

# Good
subprocess.run(['convert', filename, 'output.png'], check=True)

# YAML Deserialization
# Bad: Can execute arbitrary code
import yaml
data = yaml.load(user_input)

# Good: Use safe loader
data = yaml.safe_load(user_input)

# Path Traversal
# Bad
with open(os.path.join('/data', user_filename)) as f:
    return f.read()

# Good
import os.path
full_path = os.path.realpath(os.path.join('/data', user_filename))
if not full_path.startswith('/data/'):
    raise ValueError("Invalid path")
```

### Go

```go
// SQL Injection
// Bad
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)

// Good
db.Query("SELECT * FROM users WHERE id = $1", userID)

// Path Traversal
// Bad
filepath.Join(baseDir, userInput)

// Good
cleanPath := filepath.Clean(userInput)
fullPath := filepath.Join(baseDir, cleanPath)
if !strings.HasPrefix(fullPath, baseDir) {
    return errors.New("invalid path")
}

// Template Injection
// Bad: Using text/template with user content
t := template.New("").Parse(userTemplate)

// Good: Use html/template for HTML output
import "html/template"
t := template.New("").Parse(userTemplate)
```

### Java

```java
// SQL Injection
// Bad
String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);

// Good
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
stmt.setString(1, userId);

// XXE (XML External Entities)
// Bad
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.newDocumentBuilder().parse(userInput);

// Good
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

// Deserialization
// Bad: Deserializing untrusted data
ObjectInputStream ois = new ObjectInputStream(userInputStream);
Object obj = ois.readObject();  // Remote code execution!

// Good: Use safe alternatives like JSON
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(jsonString, MyClass.class);
```

---

## Security Review Process

### 1. Pre-Review
- Understand the feature/change context
- Identify sensitive areas (auth, crypto, data)
- Check threat model if available

### 2. During Review
- Follow data flow from input to output
- Check each trust boundary
- Verify authentication/authorization
- Look for common vulnerability patterns
- Check error handling

### 3. Post-Review
- Document findings with severity
- Suggest specific fixes
- Request re-review for critical issues
- Update threat model if needed

---

## Severity Ratings

| Severity | Description | Examples |
|----------|-------------|----------|
| Critical | Immediate exploitation risk | RCE, auth bypass, data breach |
| High | Significant security impact | SQL injection, XSS, IDOR |
| Medium | Moderate impact or harder to exploit | CSRF, information disclosure |
| Low | Minor impact | Missing headers, verbose errors |
| Info | Best practice recommendations | Code quality, hardening suggestions |

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [Secure Coding Guidelines](https://best.openssf.org/)
