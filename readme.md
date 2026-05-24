Hybrid Post-Quantum VPN

A centralized hybrid post-quantum VPN prototype built in Rust using ML-KEM-768, X25519, ChaCha20-Poly1305, and TUN-based encrypted tunneling. The project demonstrates secure client/server orchestration, centralized VPN management, live heartbeats, encrypted UDP transport, and post-quantum key exchange research.

Features
Hybrid Post-Quantum Handshake
ML-KEM-768
X25519
HKDF-SHA256 session derivation
Encrypted VPN Tunnel
ChaCha20-Poly1305 authenticated encryption
UDP-based transport
Layer 3 TUN interfaces
Centralized Management Plane
Web-based dashboard
Live client/server monitoring
Heartbeat tracking
Dynamic configuration distribution
Secure Enrollment System
Bootstrap enrollment tokens
Persistent agent authentication
Managed client/server assignments
Cross Platform
Windows client support
Linux VPN server support
Runtime Monitoring
Traffic statistics
Public IP tracking
Alert system
Live logs
Architecture
Windows Client
    |
    | Encrypted UDP Tunnel
    v
Linux VPN Server
    |
    | Management API
    v
Centralized Manager Dashboard
Cryptography Stack
Component	Algorithm
Classical Key Exchange	X25519
Post-Quantum KEM	ML-KEM-768
Session Derivation	HKDF-SHA256
Tunnel Encryption	ChaCha20-Poly1305
Technologies Used
Rust
Tokio
Axum
Tauri
tun-rs
SQLite
Reqwest
VMware
Wintun
Project Structure
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
Requirements
Windows Client
Windows 10/11
Wintun driver
Administrator PowerShell
Linux Server
Ubuntu 22.04+
Root privileges
UDP port 9000 open
Installation
Clone Repository
git clone https://github.com/KavindaSandaru/hybrid-pq-vpn.git

cd hybrid-pq-vpn
Build Project
cargo build
Run Manager
./target/debug/ntz-proto manager \
  --bind 0.0.0.0:8080 \
  --admin-user admin \
  --admin-pass admin123
Run VPN Server (Linux)
sudo ./target/debug/ntz-proto server \
  --management-url http://MANAGER_IP:8080 \
  --enrollment-token SERVER_TOKEN \
  --node-name lab-server-1 \
  --verbose
Run VPN Client (Windows)
.\target\debug\ntz-proto.exe client `
  --management-url http://MANAGER_IP:8080 `
  --enrollment-token CLIENT_TOKEN `
  --device-name "Windows-Client" `
  --verbose
Demonstration

The project demonstrates:

Hybrid post-quantum VPN handshake
Encrypted UDP tunneling
TUN interface routing
Dynamic VPN configuration
Centralized management
Live heartbeat monitoring
Real-time policy enforcement
Testing
Verify Tunnel Interface
Windows
ipconfig
Linux
ip addr
Verify Routing
route print
ip route
Verify Encrypted Traffic

Wireshark filter:

udp.port == 9000
Verify Connectivity
ping 1.1.1.1
curl ifconfig.me
Security Notes

This project is a research and educational prototype intended for demonstrating hybrid post-quantum VPN architecture concepts. It is not production-ready and requires additional hardening, scalability testing, certificate management, and security auditing before real-world deployment.

Future Improvements
Multi-server failover
MFA support
Mobile client support
Distributed manager clustering
Automatic load balancing
Certificate-based authentication
Advanced routing policies
Screenshots

Add screenshots here:

Manager dashboard
Client runtime
Wireshark encrypted traffic
Tunnel interface
Tauri desktop application
Author

Kavinda Sandaru

License

MIT License
