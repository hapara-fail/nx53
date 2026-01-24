# nx53

[![Rust CI](https://github.com/hapara-fail/nx53/actions/workflows/ci.yml/badge.svg)](https://github.com/hapara-fail/nx53/actions/workflows/ci.yml)

**High-Performance DNS Firewall & Amplification Mitigation Engine**

**nx53** is a lightweight, mission-critical firewall daemon written in **Rust**, optimized for Debian-based Linux environments. It operates as a protective layer for Public DNS Resolvers, specifically targeting the detection and mitigation of **DNS Amplification Attacks** (DDoS).

---

## 🛡️ Objective

The primary objective of nx53 is to protect open DNS resolvers from being exploited as amplifiers in DDoS attacks. It achieves this by:

- **Protocol Awareness:** Inspecting DNS traffic (Port 53 UDP/TCP) at wire speed.
- **Behavioral Analysis:** Identifying and blocking abusive traffic patterns without relying solely on static blacklists.
- **Kernel Integration:** Enforcing drop rules directly in the Linux kernel via Netfilter for minimal overhead.

---

## 🚀 Installation & Management

### Quick Install (Debian/Ubuntu)

The easiest way to install nx53 is to run the automated installer. This will download dependencies, compile the project, install the binary, set up the systemd service, and generate man pages and shell completions.

```bash
curl -s -S -L https://raw.githubusercontent.com/hapara-fail/nx53/main/install.sh | sh -s -- -v
```

Alternatively using `wget`:

```bash
wget --no-verbose -O - https://raw.githubusercontent.com/hapara-fail/nx53/main/install.sh | sh -s -- -v
```

During installation, you will be prompted to select a traffic profile (Home, School, Enterprise, Datacenter).

### Uninstallation

We provide a dedicated cleanup script to remove nx53 and all associated components (service, configs, man pages, completions).

```bash
curl -s -S -L https://raw.githubusercontent.com/hapara-fail/nx53/main/uninstall.sh | sudo sh
```

### Manual Build

If you prefer to build manually:

```bash
git clone https://github.com/hapara-fail/nx53.git
cd nx53
cargo build --release
sudo cp target/release/nx53 /usr/local/bin/
```

---

## ✨ Core Features

- **Heuristic Mitigation:** Uses a "First-Packet" rule and "Escape Hatch" logic to differentiate between legitimate users and attack scripts.
- **Zero-Cost Abstractions:** Built with Rust for memory safety and high throughput on minimal hardware.
- **Hybrid Operation:** Supports both automated intelligent filtering and manual static blocklists/whitelists.
- **Real-Time Telemetry:** Provides instant visibility into attack metrics and dropped IPs.

---

## 🧠 The Logic Engine

nx53 employs a **Dynamic Behavioral Inspection** engine to stop attacks without false positives.

### The Problem

DNS Amplification attacks involve spoofed IPs flooding a resolver with queries for a single, specific domain to generate large response packets.

### The Solution

1.  **Traffic Monitoring:** Continuously monitors ingress DNS queries.
2.  **Anomaly Detection:** Identifies domains receiving disproportionate traffic.
3.  **The "First-Packet" Rule:** If a **new** IP's very first query is for a flagged "High-Volume" domain, it is immediately marked as hostile and blocked.
4.  **The "Escape Hatch" (Legitimacy Validation):** If an IP queries a _different_ domain (one not under attack), it is re-classified as a legitimate user and whitelisted.

---

## ⚙️ CLI Specification

The software is controlled via a standard Command Line Interface.

| Command       | Arguments                 | Description                                                                         |
| :------------ | :------------------------ | :---------------------------------------------------------------------------------- |
| `nx53 block`  | `<ip/domain>`             | Adds a static rule to drop all packets from an IP or specific domain queries.       |
| `nx53 allow`  | `<ip/domain>`             | Adds a static rule to whitelist an IP or domain (bypasses all checks).              |
| `nx53 toggle` | `intelligent` \| `manual` | Toggles the active status of the heuristic engine or manual rulesets independently. |
| `nx53 stats`  | `[--json]`                | Displays real-time telemetry: attack counts, dropped IPs, and resource usage.       |
| `nx53 flush`  | `all` \| `banned`         | Clears current iptables chains managed by nx53.                                     |

---

## 💻 Tech Stack

- **Language:** [Rust](https://www.rust-lang.org/)
- **Packet Capture:** `pcap` / `af_packet`
- **Concurrency:** `Tokio` / `DashMap` for efficient state management.
- **Firewall:** `iptables` / Linux Netfilter

---

## ⚠️ Disclaimer

- **Root Privileges:** nx53 requires root access to manage network interfaces and firewall rules.
- **Compatibility:** Designed primarily for **Debian-based Linux** systems.
- **Use Responsibly:** This tool modifies kernel networking rules. Ensure you have out-of-band access to your server (e.g., VNC/Console) before deploying in production.

---

## 🤝 Contributing

Contributions are welcome! To ensure changes are processed quickly and correctly, please review our **[Contributing Guidelines](https://github.com/hapara-fail/nx53/blob/main/CONTRIBUTING.md)** before submitting.

If you have ideas for improvements, new tools, bug fixes, or blog post topics, please feel free to:

- **Open an Issue** on GitHub using our standardized templates.
- **Submit a Pull Request** with your proposed changes.
- Join our [Discord server](https://www.hapara.fail/discord) to discuss.

You can also find donation options [here](https://hapara.fail/contribute).

---

## 📄 License

This project is licensed under the terms specified at [www.hapara.fail/license](https://www.hapara.fail/license).
