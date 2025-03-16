# Understanding Server-Side Request Forgery (SSRF)

## Introduction

Server-Side Request Forgery (SSRF) is a sophisticated web security vulnerability that occurs when an attacker can manipulate a server into making HTTP requests to an unintended location. This vulnerability exploits the trust relationship between servers and internal systems, allowing attackers to bypass network security controls, access restricted services, and potentially compromise entire infrastructure environments. SSRF has become increasingly critical in today's cloud-native and microservice-oriented architectures where internal API communication is commonplace.

## How SSRF Works

At its core, SSRF manipulates functionality on the server that makes network requests. Many web applications include features that fetch remote resources, such as:

- URL validation services
- Webhook implementations
- PDF generators that fetch remote content
- API integrations that forward requests
- Image processors that load external images
- Document/media importers

When these features accept user input to determine the destination URL without proper validation, attackers can redirect requests to unintended destinations, including:

1. Internal services behind firewalls
2. Cloud provider metadata services
3. Internal network resources
4. Localhost services
5. Private networks inaccessible from the internet

## Attack Vectors and Techniques

### Basic SSRF

The simplest form of SSRF involves manipulating a URL parameter to point to an internal resource:

**Original Request:**
```
POST /fetch-data HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

url=https://api.example.com/data
```

**Malicious Request:**
```
POST /fetch-data HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

url=http://internal-service.local/admin
```

### Bypassing Common Defenses

Attackers employ various techniques to bypass SSRF protections:

#### 1. IP Address Obfuscation
- Decimal notation: `http://2130706433/` (equivalent to 127.0.0.1)
- Hexadecimal: `http://0x7f000001/` (equivalent to 127.0.0.1)
- Octal: `http://0177.0.0.1/` (equivalent to 127.0.0.1)

#### 2. DNS Rebinding
Using a controlled domain that initially resolves to an allowed IP, then quickly switches to an internal IP after validation checks have passed.

#### 3. URL Schema Abuse
- `file:///etc/passwd` - Access local files
- `dict://internal-service:11211/stat` - Access memcached
- `gopher://127.0.0.1:25/` - Interact with SMTP

#### 4. Redirection Exploitation
Using open redirects on trusted domains to bypass URL filtering:
```
https://trusted-domain.com/redirect?url=http://internal-service/
```

### Cloud Environment Attacks

Cloud environments are particularly vulnerable to SSRF due to metadata services:

- AWS: `http://169.254.169.254/latest/meta-data/`
- GCP: `http://metadata.google.internal/`
- Azure: `http://169.254.169.254/metadata/instance`

Accessing these endpoints can expose:
- Access tokens and credentials
- Instance information
- User data
- Network configuration

## Impact and Consequences

Successful SSRF attacks can lead to:

1. **Information Disclosure**: Accessing sensitive internal data
2. **Authentication Bypass**: Targeting internal authentication services
3. **Remote Code Execution**: Chaining with other vulnerabilities
4. **Internal Service Exploitation**: Attacking unprotected internal services
5. **Lateral Movement**: Pivoting to other systems in the network
6. **Data Exfiltration**: Extracting sensitive information
7. **Denial of Service**: Overwhelming internal services with requests

## Real-World Examples

Several high-profile SSRF vulnerabilities have demonstrated the severity of this attack vector:

1. **Capital One Breach (2019)**: An SSRF vulnerability in a WAF allowed an attacker to access AWS metadata and extract credentials, resulting in the exposure of 100+ million customer records.

2. **Gitlab SSRF (CVE-2021-22205)**: A critical vulnerability in GitLab's ExifTool integration allowed attackers to conduct SSRF attacks leading to RCE.

3. **Shopify SSRF (2019)**: A vulnerability in Shopify's image handling allowed attackers to scan internal networks and access AWS metadata.

4. **Uber SSRF (2018)**: Attackers leveraged an SSRF vulnerability to access Uber's internal services, ultimately compromising sensitive data of 57 million users.

## Prevention Strategies

### 1. Input Validation and Sanitization

- Implement strict allowlists for permitted domains and IPs
- Validate URL schemes (limit to http/https)
- Parse and validate URL components individually

### 2. Network-Level Controls

- Implement proper network segmentation
- Use firewall rules to restrict outbound connections
- Deploy web application firewalls with SSRF detection

### 3. Application-Level Protections

- Disable unnecessary URL schemas
- Implement DNS resolution controls
- Use a dedicated service/proxy for external requests
- Return minimal information from HTTP responses

### 4. Cloud-Specific Mitigations

- Block access to metadata services from application instances
- Use IMDSv2 in AWS (requires token headers)
- Implement least-privilege IAM policies
- Use VPC endpoints to control access to cloud services

### 5. Implementation Examples

**URL Validation in Node.js:**
```javascript
const url = require('url');

function isValidUrl(input) {
  try {
    const parsedUrl = new URL(input);
    
    // Check against allowlist of domains
    const allowedDomains = ['api.example.com', 'cdn.example.com'];
    if (!allowedDomains.includes(parsedUrl.hostname)) {
      return false;
    }
    
    // Ensure protocol is http or https
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false;
    }
    
    // Prevent private IP ranges
    const ipRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc00:|fe80:)/;
    if (ipRegex.test(parsedUrl.hostname)) {
      return false;
    }
    
    return true;
  } catch (error) {
    return false;
  }
}
```

**Safe Request Implementation in Python:**
```python
import requests
from urllib.parse import urlparse
import ipaddress

def is_internal_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved
        )
    except ValueError:
        return False

def safe_request(url):
    parsed = urlparse(url)
    
    # Check schema
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid URL schema")
    
    # Check hostname (both direct IP and resolved IP)
    if is_internal_ip(parsed.netloc):
        raise ValueError("Internal IP detected")
    
    # Resolve hostname and check IP
    try:
        ip = socket.gethostbyname(parsed.netloc)
        if is_internal_ip(ip):
            raise ValueError("Hostname resolves to internal IP")
    except socket.gaierror:
        raise ValueError("Cannot resolve hostname")
    
    # Set timeout to prevent hanging
    return requests.get(url, timeout=3)
```

## Detection and Testing

### 1. Manual Testing

- Replace URL parameters with internal services/IPs
- Try accessing localhost (127.0.0.1) and variations
- Attempt to reach cloud metadata endpoints
- Test with various URL schemas (file://, dict://, gopher://)

### 2. Automated Testing

Several tools can help identify SSRF vulnerabilities:
- Burp Suite Professional (with SSRF-focused extensions)
- OWASP ZAP
- Specialized tools like SSRFmap and Gopherus

### 3. Code Review

Look for:
- Functions that make HTTP requests with user-controlled input
- URL parsing and validation implementations
- API integrations that forward requests
- File import/export functionality

## Remediation Steps

If you discover SSRF vulnerabilities in your application:

1. Implement strict URL validation and filtering
2. Deploy network-level controls to restrict server communications
3. Review and reconfigure cloud service permissions
4. Use a dedicated service with proper access controls for external requests
5. Implement comprehensive logging and monitoring for outbound requests
6. Consider architectural changes to isolate components that process external URLs

## Conclusion

Server-Side Request Forgery represents one of the most impactful web security vulnerabilities in modern applications, particularly as organizations move to cloud and microservice architectures. Understanding SSRF mechanics, implementing robust prevention strategies, and conducting regular security assessments are essential steps in protecting your systems from these sophisticated attacks.

By maintaining strong boundaries between user input and server-side request generation, organizations can significantly reduce their exposure to SSRF vulnerabilities and the potentially devastating consequences they can bring.
