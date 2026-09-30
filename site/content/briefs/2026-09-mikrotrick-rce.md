---
title: MikroTik RouterOS Authentication Bypass and RCE
slug: 2026-09-mikrotrick-rce
description: The 'MikroTrick' campaign exploits vulnerabilities in the RouterOS SSH service to achieve unauthenticated remote code execution and administrative account persistence.
date: "2026-09-30T15:12:59Z"
lastmod: "2026-09-30T16:22:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - authentication-bypass
  - network-security
  - mikrotrick
vendors:
  - MikroTik
products:
  - RouterOS (< 6.49.21)
  - RouterOS (7.0 <= 7.23.3)
  - RouterOS (7.24.0 <= 7.24.1)
  - RouterOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The MikroTrick campaign exploits vulnerabilities in MikroTik RouterOS SSH services (port 22) to gain unauthenticated remote code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The session comes up as full administrator... Actions are logged as ssh:-2@<ip>.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: The default mode plants an account instead... /user add name=hacker group=full
    confidence_band: high
cves:
  - id: CVE-2026-86060
    cvss: 9.8
    epss: 0.01849
  - id: CVE-2026-67279
    cvss: 6.5
    epss: 0.01027
references:
  - https://www.exploit-db.com/exploits/52683
  - CVE-2026-86060
  - CVE-2026-67279
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3661
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Operations
  immediate_actions:
    - action: Upgrade all MikroTik RouterOS instances to 6.49.21, 7.23.4, or 7.24.2.
      owner: Network Operations
      due: 24h
      evidence: Exploit requires patching of CVE-2026-86060.
  mitigation_plan:
    - priority: immediate
      action: Block SSH access from untrusted networks to RouterOS devices.
      owner: Network Operations
      addresses: CVE-2026-86060
      evidence: Exploit relies on unauthenticated SSH session initialization.
updates:
  - at: "2026-09-30T16:22:26Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3661
---

The 'MikroTrick' campaign exploits a series of vulnerabilities in the MikroTik RouterOS SSH service to achieve unauthenticated remote code execution. Active since September 2026, this threat leverages a sequence of bugs in the SSH session handling mechanism to bypass authentication gates. By initiating an unauthenticated session and manipulating the state machine via a forced rekeying process, an attacker can escalate privileges to full administrative control (the 'full policy set'). The exploit essentially tricks the system into treating a custom, attacker-controlled policy mask as legitimate during the login helper process. Once control is gained, the attacker typically plants a persistent administrative account, 'hacker', to ensure ongoing access. This vulnerability affects multiple versions across both the 6.x and 7.x branches of RouterOS. Defenders should prioritize patching or restricting SSH access to trusted management subnets.

## Attack Chain

1. Attacker sends a user authentication request with the username '-2', which is rejected by the server but persists as a 'pending' state.
2. Attacker triggers a SSH rekeying request before completing any authentication handshake.
3. The rekeying process exploits CVE-2026-67279, causing the server to lose its mandatory authentication gate check.
4. Attacker opens an unauthenticated session channel using the 'pending' '-2' username state.
5. Attacker spawns the interactive shell, invoking '/nova/bin/login' which consumes the identity and policy-mask values provided by the attacker.
6. Attacker provides a malicious identity ('0') and policy mask ('4294967295'), which the login helper treats as elevated permissions (CVE-2026-86060).
7. The SSH session is promoted to full administrative rights, granting the attacker control over the RouterOS console.
8. Attacker executes system commands to add a new user 'hacker' with 'full' group privileges for persistent access.

## Impact

Successful exploitation results in full administrative control over the affected MikroTik router. Attackers can leverage this to exfiltrate configurations, intercept traffic, or pivot into the internal network. The campaign has been observed in the wild since September 2, 2026, posing a direct threat to any internet-facing RouterOS device.

## Recommendation

1. Upgrade RouterOS to the patched versions: 6.49.21, 7.23.4, or 7.24.2 immediately.
2. Restrict access to the SSH service (port 22) to specific, trusted management IP addresses using firewall filters.
3. Audit existing user accounts for any unauthorized entries, specifically looking for the 'hacker' user or accounts created with 'full' group privileges.
4. Deploy network-based detection to monitor for suspicious SSH authentication failures or anomalous rekeying behavior targeting network infrastructure.
