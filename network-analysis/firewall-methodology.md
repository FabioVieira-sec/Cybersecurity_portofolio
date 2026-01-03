# 🧱 Firewall Fundamentals & Network Hardening

Understanding how to control traffic flow is the backbone of network defense. This documentation covers my practical experience with both Windows and Linux firewall environments.

## 🛡️ Firewall Architectures
* **Stateless:** Fast packet filtering based on static rules (L3/L4).
* **Stateful:** Tracks connection state, offering higher security by monitoring the context of traffic.
* **Proxy (Application-Level):** Deep packet inspection at L7.
* **NGFW:** Integrated threat intelligence and heuristic analysis.

## 🪟 Windows Defender Firewall (Hands-on)
During my practical labs, I practiced auditing and creating rules to mitigate unauthorized access:
* **Case Scenario:** Blocking all inbound SSH traffic except for a specific Management IP.
* **Key Finding:** Identified rules like "Infra team" which allowed access only from `192.168.13.7`, following the Principle of Least Privilege.

## 🐧 Linux Firewall Management (Netfilter)
I am proficient in managing Linux firewalls using various utilities:
* **iptables/nftables:** The core frameworks for packet filtering.
* **ufw (Uncomplicated Firewall):** * `sudo ufw deny 22/tcp` - Closing attack surface.
    * `sudo ufw status numbered` - Auditing existing rules for cleanup.

> **Practical Application:** These skills are applied in every lab where I need to secure a compromised host or prevent lateral movement during an incident response simulation.
