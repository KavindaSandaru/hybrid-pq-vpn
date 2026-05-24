# NTZ Proto

NTZ Proto is a managed Rust VPN prototype that demonstrates a hybrid post-quantum handshake for a full-tunnel VPN. The system now has three deployable pieces:

- `manager`: central web dashboard and enrollment API
- `server`: managed Linux VPN gateway with TUN, UDP tunnel, NAT, firewall rules, and DNS-over-HTTPS proxying
- `client`: Windows or Linux endpoint software that enrolls with the manager, receives policy, creates a TUN interface, and connects to the assigned VPN server

The cryptographic handshake combines X25519 with ML-KEM-768, derives a session key with HKDF-SHA256, and encrypts tunnel packets with ChaCha20-Poly1305. Encrypted packet nonces are tracked so repeated ciphertexts are dropped.

## Project Goals Covered

- Working UDP VPN tunnel over a TUN interface
- Hybrid post-quantum key exchange using ML-KEM-768 and X25519
- Authenticated client enrollment through single-use bootstrap tokens
- Admin dashboard for tokens, server nodes, clients, assignments, egress IPs, firewall destinations, and health status
- Linux server automation for routing, forwarding, NAT, SNAT, and DNS proxying
- Windows and Linux client software for managed endpoint connections

## Requirements

Install Rust stable and build the project:

```bash
cargo build
```

Linux server requirements:

- Run as `root`
- TUN support at `/dev/net/tun`
- `ip`, `iptables`, and `sysctl`
- A reachable UDP port, default `9000`

Windows client requirements:

- Run PowerShell or Command Prompt as Administrator
- Place the official `wintun.dll` next to `target\debug\ntz-proto.exe` or in the project directory
- Allow the client to add routes and DNS settings

## 1. Start the Manager Dashboard

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

Sign in with the admin username and password. Change the default password when demonstrating on a shared network.

## 2. Configure Global VPN Settings

In the dashboard, check these fields before enrolling agents:

- Public endpoint: the IP and UDP port clients can reach, for example `203.0.113.10:9000`
- Server listen address: usually `0.0.0.0:9000`
- Client CIDR: default `10.44.0.0/24`
- Server TUN IP: default `10.44.0.1`
- NAT interface: Linux WAN interface, for example `ens33`, `eth0`, or `enp0s3`
- Setup NAT automatically: enabled for the normal demo

Every save increments the manager config version. Agents poll and report whether they are current.

## 3. Enroll a Linux Server Node

In the dashboard:

1. Create a bootstrap token with type `Server node`.
2. Use `Copy run command`, or run manually:

```bash
sudo ./target/debug/ntz-proto server \
  --management-url http://MANAGER_IP:8080 \
  --enrollment-token SERVER_TOKEN \
  --node-name lab-server-1 \
  --verbose
```

After enrollment, the server appears under Server fleet. The manager can enable or disable it, edit its public endpoint, set the NAT interface, and show connected client counts.

## 4. Enroll a Client Device

In the dashboard:

1. Create a bootstrap token with type `Client device`.
2. Use `Copy run command`, or run manually.

Windows Administrator shell:

```powershell
.\target\debug\ntz-proto.exe client `
  --management-url http://MANAGER_IP:8080 `
  --enrollment-token CLIENT_TOKEN `
  --device-name kavinda-laptop `
  --verbose
```

Linux root shell:

```bash
sudo ./target/debug/ntz-proto client \
  --management-url http://MANAGER_IP:8080 \
  --enrollment-token CLIENT_TOKEN \
  --device-name linux-client-1 \
  --verbose
```

The client enrolls once, stores its agent credentials in `state/client/agent_state.json`, receives its assigned tunnel IP, connects to the assigned server, performs the hybrid handshake, and starts encrypting TUN packets over UDP.

## 5. Manage Clients from the Dashboard

The Client inventory section lets administrators:

- Enable or disable a client
- Assign the client to a server node
- Edit the client's tunnel IP
- Set a per-client egress IP override
- Remove a client so it must enroll again
- Watch heartbeat, error, and applied config status

The Server fleet section lets administrators:

- Enable or disable a server
- Change public endpoint and listen address
- Update NAT interface and max clients
- Remove retired server nodes
- Watch health, connected client count, and config version

## Demo Checklist

Use this sequence for a final project demonstration:

1. Start `manager` and log into the dashboard.
2. Set the server public endpoint and NAT interface.
3. Create a server token and enroll the Linux server.
4. Create a client token and enroll the Windows or Linux client.
5. Confirm both agents show healthy heartbeats.
6. Confirm the client is assigned to the server.
7. Send traffic from the client, for example `ping 1.1.1.1` or open a website.
8. Disable the client in the dashboard and show traffic stops passing.
9. Re-enable the client and show the agent applies the updated config.

## Important Prototype Notes

This is a research prototype, not a replacement for production VPN software. It demonstrates the requested architecture and control flow, but it should still be reviewed before use on a real network.

- The server runtime is Linux-only because it programs TUN, routing, NAT, and iptables.
- Windows client route and DNS setup requires Administrator permission.
- If global structural settings change, such as TUN name, address, MTU, or server listen address, restart the affected agent so it can recreate the interface.
- Keep bootstrap tokens private. They are single-use, but anyone with an unused token can enroll an agent of that token type.
