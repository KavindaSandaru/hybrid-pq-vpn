# Hybrid Post-Quantum VPN

A centralized hybrid post-quantum VPN prototype built in Rust that demonstrates secure encrypted tunneling, hybrid post-quantum key exchange, centralized VPN orchestration, and managed endpoint enrollment. The project combines ML-KEM-768 and X25519 for hybrid cryptography, encrypted UDP transport with ChaCha20-Poly1305, and a web-based management dashboard for controlling VPN infrastructure and clients.

This research prototype demonstrates modern VPN architecture concepts including TUN-based encrypted tunneling, centralized policy management, dynamic configuration distribution, secure enrollment workflows, heartbeat monitoring, and post-quantum cryptographic experimentation. 

---

# Features

## Hybrid Post-Quantum Cryptography

* ML-KEM-768 post-quantum key encapsulation
* X25519 elliptic curve key exchange
* HKDF-SHA256 session key derivation
* Hybrid classical + post-quantum handshake
* Nonce replay protection

## Encrypted VPN Tunnel

* ChaCha20-Poly1305 authenticated encryption
* UDP-based encrypted transport
* Layer 3 TUN interfaces
* Full tunnel VPN routing
* Secure encrypted packet forwarding

## Centralized Management Plane

* Web-based admin dashboard
* Dynamic VPN configuration distribution
* Live client and server monitoring
* Heartbeat tracking and health reporting
* Real-time policy management

## Secure Enrollment System

* Single-use bootstrap enrollment tokens
* Persistent agent authentication
* Managed client/server assignments
* Controlled endpoint provisioning

## Cross Platform Support

* Windows VPN client support
* Linux VPN server support
* Managed Rust-based agents

## Runtime Monitoring

* Traffic statistics
* Public IP tracking
* Live logs and alerts
* Connected client monitoring
* VPN server health status

---

# Architecture

```text
Windows/Linux VPN Client
        |
        | Encrypted UDP Tunnel
        v
Linux VPN Server
        |
        | Management API
        v
Centralized Manager Dashboard
```

The system consists of three deployable components:

* `manager` — centralized web dashboard and enrollment API
* `server` — Linux VPN gateway handling TUN routing, NAT, firewall rules, and encrypted UDP transport
* `client` — Windows or Linux VPN endpoint software for secure tunnel connectivity 

---

# Cryptography Stack

| Component              | Algorithm         |
| ---------------------- | ----------------- |
| Classical Key Exchange | X25519            |
| Post-Quantum KEM       | ML-KEM-768        |
| Session Derivation     | HKDF-SHA256       |
| Tunnel Encryption      | ChaCha20-Poly1305 |

The cryptographic handshake combines ML-KEM-768 with X25519, derives a shared session key using HKDF-SHA256, and encrypts VPN traffic using ChaCha20-Poly1305 authenticated encryption. 

---

# Technologies Used

* Rust
* Tokio
* Axum
* Tauri
* SQLite
* tun-rs
* Reqwest
* VMware
* Wintun
* iptables
* Linux TUN networking

---

# Project Structure

```text
src/
├── client.rs
├── server.rs
├── manager.rs
├── crypto_logic.rs
├── management_client.rs
├── tunnel_protocol.rs
├── agent_state.rs
└── models.rs

ntz-vpn-app/
└── Tauri desktop application
```

---

# Requirements

## General

* Rust stable toolchain
* Cargo build system

Build the project:

```bash
cargo build
```

---

## Linux VPN Server Requirements

* Ubuntu 22.04+ recommended
* Run as root
* `/dev/net/tun`
* `ip`, `iptables`, and `sysctl`
* Reachable UDP port (default `9000`)

---

## Windows Client Requirements

* Windows 10/11
* Wintun driver
* Administrator PowerShell or CMD
* `wintun.dll` available next to executable or project directory

---

# Installation & Setup

## Clone Repository

```bash
git clone https://github.com/KavindaSandaru/hybrid-pq-vpn.git

cd hybrid-pq-vpn
```

---

# Start the Manager Dashboard

```bash
./target/debug/ntz-proto manager \
  --bind 0.0.0.0:8080 \
  --admin-user admin \
  --admin-pass admin123
```

Open:

```text
http://MANAGER_IP:8080
```

The dashboard manages:

* enrollment tokens
* VPN servers
* VPN clients
* routing assignments
* health monitoring
* policy distribution



---

# Configure Global VPN Settings

Before enrolling agents, configure:

* Public endpoint
* Server listen address
* Client CIDR
* Server TUN IP
* NAT interface
* Automatic NAT setup

Example:

* Public endpoint: `203.0.113.10:9000`
* Client CIDR: `10.44.0.0/24`
* Server TUN IP: `10.44.0.1`



---

# Enroll a Linux VPN Server

```bash
sudo ./target/debug/ntz-proto server \
  --management-url http://MANAGER_IP:8080 \
  --enrollment-token SERVER_TOKEN \
  --node-name lab-server-1 \
  --verbose
```

Server responsibilities:

* TUN interface creation
* NAT and SNAT configuration
* UDP encrypted transport
* DNS-over-HTTPS proxying
* Routing and firewall management



---

# Enroll a VPN Client

## Windows

```powershell
.\target\debug\ntz-proto.exe client `
  --management-url http://MANAGER_IP:8080 `
  --enrollment-token CLIENT_TOKEN `
  --device-name "Windows-Client" `
  --verbose
```

## Linux

```bash
sudo ./target/debug/ntz-proto client \
  --management-url http://MANAGER_IP:8080 \
  --enrollment-token CLIENT_TOKEN \
  --device-name linux-client-1 \
  --verbose
```

The client:

* enrolls securely
* stores persistent credentials
* receives VPN configuration
* performs the hybrid handshake
* establishes encrypted UDP tunneling



---

# Dashboard Management Features

## Client Inventory

Administrators can:

* enable or disable clients
* assign VPN servers
* edit tunnel IPs
* configure egress IPs
* remove enrolled clients
* monitor heartbeat status

## Server Fleet

Administrators can:

* enable or disable servers
* edit public endpoints
* configure NAT interfaces
* manage client capacity
* monitor server health



---

# Demonstration Checklist

1. Start the manager dashboard
2. Configure VPN settings
3. Enroll the Linux VPN server
4. Enroll a Windows/Linux VPN client
5. Verify healthy heartbeats
6. Confirm encrypted connectivity
7. Send traffic through the VPN tunnel
8. Disable the client from dashboard
9. Verify traffic stops
10. Re-enable the client and verify reconnect



---

# Testing

## Verify Tunnel Interface

### Windows

```powershell
ipconfig
```

### Linux

```bash
ip addr
```

---

## Verify Routing

### Windows

```powershell
route print
```

### Linux

```bash
ip route
```

---

## Verify Encrypted Traffic

Wireshark filter:

```text
udp.port == 9000
```

---

## Verify Connectivity

```bash
ping 1.1.1.1
curl ifconfig.me
```

---

# Security Notes

This project is a research and educational prototype intended to demonstrate hybrid post-quantum VPN architecture concepts. It is NOT production-ready and still requires:

* security auditing
* certificate management
* scalability testing
* hardening
* authentication improvements
* production deployment review

Additional prototype limitations:

* Linux-only VPN server runtime
* Windows client requires Administrator privileges
* Bootstrap enrollment tokens must remain private
* Global structural changes may require agent restart



---

# Future Improvements

* Multi-server failover
* MFA support
* Mobile VPN clients
* Distributed manager clustering
* Automatic load balancing
* Certificate-based authentication
* Advanced routing policies
* Enhanced telemetry and analytics

---

# Screenshots

<img width="1902" height="939" alt="image" src="https://github.com/user-attachments/assets/a4918bbf-e5d7-4728-9a21-0e8919dcfdf0" />

<img width="1901" height="941" alt="image" src="https://github.com/user-attachments/assets/81efa393-4d39-4f7a-abae-981b4276db02" />

<img width="1902" height="939" alt="image" src="https://github.com/user-attachments/assets/ad10a41c-4eb4-44e7-8750-c499cb005449" />

<img width="1897" height="939" alt="image" src="https://github.com/user-attachments/assets/800f35e3-b614-46a4-a9f1-3797fb234465" />

<img width="1917" height="1031" alt="image" src="https://github.com/user-attachments/assets/da720aa8-fa02-4e83-a6aa-ffa59c60a1be" />


---

# Author

Kavinda Sandaru

---

# License

MIT License
