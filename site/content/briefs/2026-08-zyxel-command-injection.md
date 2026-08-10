---
title: OS Command Injection Vulnerability in Zyxel WAH7601
slug: 2026-08-zyxel-command-injection
description: An OS command injection vulnerability in Zyxel WAH7601 devices (CVE-2026-13206) allows unauthenticated remote attackers to execute arbitrary system commands.
date: "2026-08-10T13:31:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-13206
  - command-injection
  - zyxel
  - network-device
  - rce
vendors:
  - Zyxel
products:
  - WAH7601
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper neutralization of special elements used in an OS command ('OS command injection') vulnerability in Zyxel Networks WAH7601 allows OS Command Injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows OS Command Injection.
    confidence_band: high
cves:
  - id: CVE-2026-13206
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13206
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory Zyxel WAH7601 assets across the organization.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-13206 affects Zyxel WAH7601.
  mitigation_plan:
    - priority: immediate
      action: Patch firmware on all Zyxel WAH7601 devices to version > 20072026.
      owner: IT Operations
      addresses: CVE-2026-13206
      evidence: Source states affected versions include 20072026.
---

Zyxel WAH7601 mobile Wi-Fi devices are vulnerable to an OS command injection flaw tracked as CVE-2026-13206. This vulnerability arises from the improper neutralization of special elements within OS commands, allowing an attacker to inject and execute arbitrary commands on the underlying device operating system. The flaw affects all firmware versions up to and including 20072026. Given the critical CVSS base score of 9.8, this vulnerability poses a severe risk to network infrastructure security. Defenders should treat this as a high-priority patch item, as successful exploitation results in full device compromise, potentially facilitating lateral movement into connected networks or interception of wireless traffic.

## Impact

Successful exploitation of CVE-2026-13206 allows unauthenticated attackers to achieve remote code execution (RCE) on the Zyxel WAH7601. This can lead to total device takeover, persistence through firmware manipulation, exfiltration of administrative credentials, and the redirection of wireless traffic for man-in-the-middle attacks within the local environment.

## Recommendation

- Identify all Zyxel WAH7601 devices on the internal network that are reachable via management interfaces.
- Apply the latest firmware updates provided by Zyxel to address CVE-2026-13206.
- Restrict management interface access to trusted administrative source IPs using local firewall or VLAN segmentation rules.
- Monitor logs for unusual web management traffic or unexpected system command execution originating from the device.
