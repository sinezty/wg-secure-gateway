# 🛡️ WireGuard Secure Gateway

<div align="center">

![WireGuard Gateway & SSH Security Installer](docs/screenshot.png)

**One-click WireGuard VPN server & SSH security hardening for Debian/Ubuntu.**

[English](README.md) | [Türkçe](README_TR.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](install.sh)

</div>

---

## 📖 What is this?

A single bash script that turns a fresh VPS or server into a **fully secured WireGuard VPN server** in minutes. It handles everything: SSH hardening, firewall rules, WireGuard key generation, client config, and even QR code generation for mobile devices.

> **Looking for the client gateway?** If you want to route your entire home network through this VPN, check out 👉 [wg-client-gateway](https://github.com/sinezty/wg-client-gateway)

## ✨ Features

- 🔧 **One-Click Setup** — Fully automated for Debian 11/12/13, Ubuntu 20.04/22.04/24.04+, Raspbian, DietPi
- 🔒 **SSH Hardening** — Root login control, max auth attempts, session timeouts
- 🌐 **WireGuard VPN** — Auto key generation, client config + QR code
- 🧱 **Firewall (UFW)** — Deny incoming, allow outgoing, smart NAT handling
- 🛡️ **Fail2ban** — SSH brute-force protection out of the box
- 🔄 **Auto Updates** — Optional unattended-upgrades for security patches
- 🧹 **Clean & Dirty Install** — Works safely on fresh and existing systems
- 🌍 **DNS Selection** — Choose from Cloudflare, Google, AdGuard, or custom DNS
- ⚠️ **Error Handling** — Rollback mechanism, config backups, retry logic

## 🚀 Quick Start

> ⏱️ Installation takes approximately **2–5 minutes**.

```bash
curl -fsSL https://raw.githubusercontent.com/sinezty/wg-secure-gateway/main/install.sh | sudo bash
```

## 📦 Installation

```bash
# Option 1: Direct execution (recommended)
curl -fsSL https://raw.githubusercontent.com/sinezty/wg-secure-gateway/main/install.sh | sudo bash

# Option 2: Download first, then run
wget https://raw.githubusercontent.com/sinezty/wg-secure-gateway/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

## ⚙️ Configuration

The script walks you through an interactive setup:

| Setting | Default | Description |
|---------|---------|-------------|
| WireGuard Port | 41194 | UDP port for the VPN tunnel |
| DNS Provider | Cloudflare | DNS used by VPN clients (see table below) |
| Auto Updates | Yes | Automatic security patches via unattended-upgrades |
| Reset UFW | No | Option to wipe existing firewall rules |
| Disable Root Login | Yes | Blocks SSH root access (auto-skipped if you're root) |

### DNS Providers

| # | Provider | Primary | Secondary |
|---|----------|---------|-----------|
| 1 | Cloudflare | `1.1.1.1` | `1.0.0.1` |
| 2 | Google | `8.8.8.8` | `8.8.4.4` |
| 3 | AdGuard | `94.140.14.14` | `94.140.15.15` |
| 4 | Custom | User-defined | User-defined |

## 📋 What Happens During Installation

```
1. System Checks         → Root, OS version, existing configs
2. Package Installation  → WireGuard, UFW, fail2ban, etc. (with retry)
3. SSH Hardening         → Custom port, security limits
4. Network Detection     → Interface, public IP (multiple fallbacks)
5. WireGuard Setup       → Key generation, server & client configs
6. Firewall (UFW)        → Rules + NAT/MASQUERADE routing
7. Services              → fail2ban, WireGuard, auto-updates
8. QR Code               → Scan with your phone to connect
```

## 📁 Generated Files

| File | What it is |
|------|------------|
| `/etc/wireguard/wg0.conf` | Server configuration |
| `/etc/wireguard/client.conf` | Client configuration (share this!) |
| `/var/log/wg_setup.log` | Full installation log |
| `~/installation_notes.txt` | Summary with connection details |

## 🔐 Security Measures

| Layer | Protection |
|-------|-----------|
| SSH | Max 3 auth tries, session timeout |
| SSH | Root login disabled (unless you're root) |
| SSH | fail2ban brute-force protection |
| Firewall | UFW: deny all incoming, allow outgoing |
| VPN | Full WireGuard encryption |
| System | Automatic security updates (optional) |
| Backup | UFW rules backed up before changes |

## 💻 Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, Raspbian, or DietPi
- **Access**: Root or sudo privileges
- **Network**: Active internet connection

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| 👉 **[wg-client-gateway](https://github.com/sinezty/wg-client-gateway)** | Turn a Raspberry Pi into a VPN gateway — route your entire home network through this VPN server |

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss.

## 📝 License

MIT

## 👤 Author

BarışY