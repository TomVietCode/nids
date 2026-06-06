# NIDS Debugging Prompts

> **System context (shared across all prompts)**
> - VPS IP: `152.42.209.91`, interface `eth0`
> - Attacker/tester machine IP: `222.252.24.15`
> - Service: `sudo systemctl start nids` → runs `main.py` (Flask + SocketIO + Scapy)
> - Key source files: `core/sniffer.py`, `core/analyzer.py`, `core/responder.py`, `api/routes.py`, `config.py`
> - Database: SQLite at `db/nids.sqlite` (ORM models: `PacketLog`, `AlertHistory`, `IPList`)

---

## Prompt 1 — Noisy Packet Logs (Too Many Irrelevant Packets)

**Context:**
I'm running a custom Python NIDS on a VPS (`152.42.209.91`). The packet sniffer uses Scapy with this BPF filter in `sniffer.py`:
```python
sniff(iface="eth0", filter="not port 5000", prn=self._handle, store=False)
```
Every captured packet (regardless of source) is logged to SQLite via a bulk-insert buffer. In the packet log CSV I see a large volume of packets from IPs like `205.210.31.212`, `177.38.71.226`, and even `152.42.209.91` (the VPS itself — its own outbound replies).

**Problem:**
The packet log is flooded with noise: internet background radiation, VPS-generated response traffic, SSH keepalives, and unrelated services. I only want to log packets that are *relevant to threat detection* (inbound, from external IPs, not my own VPS).

**Questions for the AI:**
1. What changes should I make to the Scapy BPF filter string in `_capture_loop()` to exclude the VPS's own outbound traffic (`src host 152.42.209.91`) and limit capture to inbound packets only?
2. Should filtering happen at the BPF level (most efficient) or inside `_handle()` / `_extract_meta()` in Python? What are the tradeoffs?
3. Should I also add a Python-level `IGNORE_IPS` set in `config.py` and check it inside `_handle()` before appending to the buffer, as a secondary filter for known benign IPs like my own VPS address?
4. Will filtering out `src host 152.42.209.91` at the BPF level break any detection rule — specifically DET-04 (flood) which tracks `src_ip` from `meta`, or DET-03 (ARP spoof) which reads ARP packets before the IP check?

---

## Prompt 2 — iptables DROP Not Stopping Attacks + Rate Limit Verification

**Context:**
In `responder.py`, when an alert has severity `HIGH` or `CRITICAL`, `_apply_block()` runs:
```python
subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], ...)
```
When severity is `MEDIUM`, `_apply_rate_limit()` runs:
```python
iptables -A INPUT -s <ip> -m limit --limit 10/min -j ACCEPT
```
An attacker IP was confirmed in the iptables DROP list (`sudo iptables -L -n`), but attacks still appear to get through.

**Problem:**
The iptables rules are appended with `-A` (append to end of chain). If there are existing `ACCEPT` rules earlier in the INPUT chain (e.g., from ufw, fail2ban, or the default policy), the DROP rule may never be reached. Also, the rate-limit rule uses `-j ACCEPT` which is a *permissive* rule, not a DROP-after-limit pattern.

**Questions for the AI:**
1. How do I check if earlier rules in the INPUT chain are matching traffic before my DROP rule? (What `iptables -L -n --line-numbers` output should I look for?)
2. Should `_apply_block()` use `-I INPUT 1` (insert at top) instead of `-A INPUT` (append to bottom) to ensure the DROP rule has priority? What are the risks?
3. The current rate-limit rule is `iptables -A INPUT -s <ip> -m limit --limit 10/min -j ACCEPT`. This accepts packets *up to* the limit but has no DROP for packets *over* the limit. How should the rule be rewritten to actually cap/drop excess traffic? (Show the correct two-rule pattern.)
4. Is `RATE_LIMIT_RULE = "10/min"` from `config.py` a sensible default for a MEDIUM-severity alert, or is it too permissive? What value would you recommend for SSH brute-force deterrence?

---

## Prompt 3 — Ping Sweep False Positive: VPS's Own IP Triggers MEDIUM Alert

**Context:**
Detection rule DET-05 in `analyzer.py` (`_detect_ping_sweep`) works like this:
```python
def _detect_ping_sweep(self, meta: dict, out: list[dict]) -> None:
    src = meta["src_ip"]          # <-- uses src_ip of each ICMP packet
    dq = self.ping_sweep[src]
    dq.append((now, meta["dst_ip"]))
    ...
    if len(unique_targets) >= config.PING_SWEEP_HOST_THRESHOLD:  # default: 10 hosts
        out.append({"src_ip": src, "threat_type": "PING_SWEEP", "severity": "MEDIUM", ...})
```
When I run `sudo nmap -sn 152.42.209.91/24` from my machine (`222.252.24.15`), the VPS (`152.42.209.91`) sends ICMP echo-replies back to my machine. The sniffer on the VPS captures those reply packets, and because the BPF filter is just `not port 5000`, it sees packets with `src_ip = 152.42.209.91` (the VPS replying) pinging many hosts in the /24 subnet — and incorrectly fires a PING_SWEEP alert for the VPS's own IP.

**Problem:**
The VPS's ICMP replies to the sweep are being misidentified as the VPS itself initiating a sweep. The real attacker is `222.252.24.15`, but the alert reports `152.42.209.91`.

**Questions for the AI:**
1. Is the root cause that the BPF filter is too broad and captures the VPS's own outbound ICMP replies? Would adding `and src not 152.42.209.91` to the Scapy filter fix this, and would it break detection of outbound attacks from the VPS itself?
2. Alternatively, should `_detect_ping_sweep()` be modified to only trigger when `meta["dst_ip"] == config.VPS_IP` (i.e., only track probes *targeting* the VPS), rather than tracking every ICMP packet by `src_ip`?
3. Should I add `VPS_IP = "152.42.209.91"` to `config.py` and use it to filter out self-generated traffic in both the sniffer and the analyzer?
4. `nmap -sn` also sends ARP requests on local subnets. Could DET-03 (ARP spoof) or DET-01 (port scan) also fire spuriously during this test? How would I verify?

---

## Prompt 4 — DDoS Test Triggers Mixed FLOOD + BRUTE_FORCE Alerts, Both src and dst IP Appear

**Context:**
I ran: `sudo hping3 -S -p 80 --flood 152.42.209.91` from `222.252.24.15`.

In `analyzer.py`, detection runs in this order per packet:
```python
def process(self, pkt, meta):
    self._detect_flood(meta, alerts)     # DET-04: checks ALL protocols, any src_ip
    if proto == "TCP":
        self._detect_port_scan(meta, alerts)   # DET-01
        self._detect_brute_force(meta, alerts) # DET-02
```
DET-04 (`_detect_flood`) counts packets per `src_ip` per second-bucket. DET-02 (`_detect_brute_force`) triggers when port 80 is in `BRUTE_FORCE_PORTS = [22, 21, 80, 443]` and SYN packets exceed 20 in 10 seconds.

**Problems observed:**
- Alerts fire for both `222.252.24.15` (attacker) *and* `152.42.209.91` (the VPS) — because the VPS sends TCP RST/ACK responses that are also captured.
- FLOOD and BRUTE_FORCE alerts interleave during the flood because hping3 sends SYN packets to port 80, which simultaneously triggers DET-04 (>500 pps) and DET-02 (>20 SYNs to port 80 in 10s).

**Questions for the AI:**
1. Why does `152.42.209.91` appear as a `src_ip` in alerts during an inbound flood? Walk through what packets the VPS generates in response to SYN flood and how the sniffer captures them.
2. The BRUTE_FORCE threshold is 20 SYN packets in 10 seconds (`BRUTE_FORCE_THRESHOLD = 20`, `BRUTE_FORCE_WINDOW_SEC = 10`). A SYN flood sends thousands per second. Should port 80 be removed from `BRUTE_FORCE_PORTS`? What is the correct semantic distinction between a flood attack on a port vs. a brute-force attack?
3. How should the detection priority be structured so that if a FLOOD alert fires for an IP, BRUTE_FORCE detection is suppressed for the same IP in that time window? Can I use the existing `_cooldown` dict to achieve this, or do I need a separate "active flood" state?
4. Should `_detect_flood` be restricted to only count inbound packets (i.e., `dst_ip == VPS_IP`) rather than all packets by src_ip?

---

## Prompt 5 — Whitelist and Blacklist Not Taking Effect

**Context:**
The `Responder._lookup_list(ip)` method queries the `IPList` table via SQLAlchemy:
```python
def _lookup_list(self, ip: str) -> Optional[str]:
    with session_scope() as s:
        row = s.scalar(select(IPList).where(IPList.ip_address == ip))
        return row.list_type if row else None
```
In `handle_alert()`:
```python
list_type = self._lookup_list(alert["src_ip"])
if list_type == "whitelist":
    self._emit(payload)
    return   # skip firewall, but still show alert
if list_type == "blacklist" or severity in config.AUTO_BLOCK_SEVERITIES:
    self._apply_block(alert["src_ip"])
```
I added `222.252.24.15` to the whitelist via the UI (`POST /api/iplist`), but alerts for that IP still appear and iptables rules are still applied.

**Problem:**
The whitelist is checked, but the alert is still *emitted* (shown on the dashboard) even for whitelisted IPs, which is by design (`self._emit(payload)` before returning). The actual bug is likely that the IP lookup is failing silently — either a DB write issue, a case/format mismatch in the IP string, or a SQLAlchemy session not committing properly.

**Questions for the AI:**
1. Walk me through how to verify that the IP was actually saved to SQLite: what SQL query or Python snippet can I run to confirm the `ip_list` table contains `222.252.24.15`?
2. In `session_scope()`, does the context manager commit automatically on exit? If the `POST /api/iplist` handler has a commit issue (e.g., exception before `session.commit()`), how would I detect it?
3. The `_apply_block()` method has an early-return guard:
   ```python
   if ip in self._blocked:
       return
   ```
   If `222.252.24.15` was blocked *before* it was added to the whitelist, it stays in `self._blocked` (an in-memory set). Subsequent alerts skip the `_apply_block()` call anyway — but is the whitelist check still happening? Could the `_blocked` set cause the logic to *appear* to work even when the DB lookup fails?
4. Why does the alert still *appear* on the dashboard even for whitelisted IPs? Is this intentional (whitelist only skips firewall action, not alerting), and if so, how should the UI communicate this distinction to the operator?
5. How do I verify that the blacklist auto-block also works correctly at startup? `_reapply_blacklist_on_boot()` runs once — if a new IP is added to the blacklist at runtime, does the iptables rule get applied immediately via `_apply_block()` in `handle_alert()`?

---

## Prompt 6 — Do Auto-Blocked IPs Automatically Appear in the Web Dashboard Blacklist?

**Context:**
When an alert with severity `HIGH` or `CRITICAL` fires, `responder.py` calls `_apply_block(ip)`, which:
1. Adds the IP to the in-memory `self._blocked` set.
2. Runs `iptables -A INPUT -s <ip> -j DROP`.

The dashboard's blacklist view is populated from `GET /api/iplist`, which queries the `IPList` SQLAlchemy model table. The `IPList` table is managed *manually* via `POST /api/iplist` (UI or API). The `_apply_block()` method **does not write to `IPList`**.

**Problem / Question:**
When an IP is automatically blocked by the NIDS (iptables DROP applied), does it automatically appear in the blacklist section of the web dashboard?

**Answer (for the AI to confirm and expand on):**
No — auto-blocked IPs do NOT appear on the dashboard blacklist. `_apply_block()` only updates:
- `self._blocked` (in-memory, lost on restart)
- `iptables` rules (kernel-level, also lost on restart unless persisted with `iptables-save`)

The `IPList` database table (which feeds the dashboard) is never updated by `_apply_block()`.

**Follow-up questions:**
1. How should I modify `_apply_block()` to also write the IP to the `IPList` table with `list_type = "blacklist"` and a `reason` like `"auto-blocked: HIGH/CRITICAL alert"`? Show the code change in `responder.py`.
2. After adding the auto-write, will `_reapply_blacklist_on_boot()` also pick up these auto-blocked IPs on next restart? Walk through the logic.
3. If an auto-blocked IP is later manually removed from the dashboard (via `DELETE /api/iplist/<ip>`), the iptables rule is NOT removed. Should `DELETE /api/iplist/<ip>` in `routes.py` also run `iptables -D INPUT -s <ip> -j DROP` to stay in sync? What are the risks?
4. How do I make iptables rules survive a VPS reboot? (`iptables-save`, `iptables-restore`, or `iptables-persistent` package)
