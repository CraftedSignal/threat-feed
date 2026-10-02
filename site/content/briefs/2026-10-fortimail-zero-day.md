---
title: Critical FortiMail Zero-Day Exploited for Arbitrary File Write
slug: 2026-10-fortimail-zero-day
description: Unauthenticated attackers are actively exploiting a path traversal and NULL byte injection vulnerability (CVE-2026-104286) in FortiMail to write arbitrary files and establish persistence.
date: "2026-10-02T06:25:40Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - persistence
  - network-security
vendors:
  - Fortinet
products:
  - FortiMail (8.0.0-8.0.1)
  - FortiMail (7.6.0-7.6.6)
  - FortiMail (7.4.0-7.4.8)
  - FortiMail (7.2.0-7.2.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: Attacker modified or added system files including web console binaries.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.006
    technique_name: 'Boot or Logon Autostart Execution: Kernel Modules and Extensions'
    evidence: Attacker added /data/etc/ld.so.preload to establish persistence.
    confidence_band: high
cves:
  - id: CVE-2026-104286
    cvss: 9.8
references:
  - https://thehackernews.com/2026/10/critical-fortimail-zero-day-flaw.html
iocs:
  - type: ip
    value: 79.141.169.187
  - type: ip
    value: 45.129.0.192
ioc_counts:
  ip: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block IOC IPs 79.141.169.187 and 45.129.0.192 at the firewall
      owner: SOC
      due: 24h
      evidence: Active exploitation reported by Fortinet and CISA
  mitigation_plan:
    - priority: immediate
      action: Upgrade FortiMail to 8.0.2, 7.6.7, 7.4.9, or branch 7.4+; otherwise apply CLI workaround
      owner: IT Operations
      addresses: CVE-2026-104286
      evidence: Vendor advisory
---

Fortinet has confirmed active, in-the-wild exploitation of a critical vulnerability (CVE-2026-104286, CVSS 9.8) impacting multiple versions of FortiMail. The flaw arises from an improper limitation of a pathname to a restricted directory combined with improper neutralization of NULL bytes, enabling unauthenticated remote attackers to perform arbitrary file writes via crafted HTTP or HTTPS requests. Threat actors are leveraging this capability to modify existing system files and inject new binaries to establish persistent unauthorized access. CISA has added this vulnerability to its Known Exploited Vulnerabilities (KEV) catalog, mandating that FCEB agencies apply patches or workarounds by October 4, 2026. Defenders must prioritize patching vulnerable versions or implementing the recommended CLI-based workarounds.

## Attack Chain

1. Attacker sends a crafted HTTP/HTTPS request targeting the FortiMail appliance.
2. The request utilizes path traversal sequences combined with NULL byte injection to bypass file system restrictions.
3. The FortiMail application incorrectly processes the request, allowing the attacker to write files outside of intended directories.
4. Attacker overwrites or modifies critical system binaries, such as /bin/smit or /data/bin/webconsole.
5. Attacker deploys malicious shared objects, such as /data/lib/liblog.so or /data/etc/ld.so.preload, to achieve arbitrary code execution.
6. Attacker modifies configuration files, including /data/etc/httpd.conf, to maintain persistent access or redirect management traffic.
7. Final objective achieved: establishment of a backdoor or persistence mechanism on the compromised appliance.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized access to the underlying operating system of the FortiMail appliance. This can lead to full system compromise, exfiltration of sensitive email data, and the use of the appliance as a pivot point into the internal network. Active exploitation has been reported, necessitating immediate attention across all enterprise environments utilizing the affected FortiMail versions.

## Recommendation

- Upgrade FortiMail appliances to the vendor-specified fixed versions immediately (8.0.2, 7.6.7, 7.4.9, or branch 7.4+).
- Implement the temporary CLI workaround: disable the IBE feature using 'config system encryption ibe' -> 'set status disable' -> 'end'.
- Restrict access to the FortiMail management interface to trusted private networks only, blocking internet-facing management access.
- Hunt for indicators of compromise, specifically looking for unauthorized modifications to /data/bin/webconsole, /data/etc/ld.so.preload, and /bin/smit.
