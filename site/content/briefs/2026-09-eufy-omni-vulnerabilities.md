---
title: Critical Vulnerabilities in Eufy Omni C20 and X10 Pro
slug: 2026-09-eufy-omni-vulnerabilities
description: Multiple vulnerabilities in Eufy Omni C20 and X10 Pro devices, including command injection, hard-coded credentials, and improper certificate validation, allow unauthenticated attackers to achieve remote code execution and credential theft.
date: "2026-09-24T16:14:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Eufy
products:
  - Omni C20 (< 1.6.4)
  - Omni X10 Pro (< 1.6.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected products are vulnerable to command injection attack that could allow an unauthenticated attacker to execute system commands during the pairing process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to run system level commands or execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Omni C20 uses hard-coded credentials that could allow an attacker to monitor log files to obtain credentials.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557.001
    technique_name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
    evidence: Omni C20 lacks proper certificate validation which could allow an attacker to perform a man-in-the-middle attack.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-267-02
  - https://www.cve.org/CVERecord?id=CVE-2026-93289
  - https://www.cve.org/CVERecord?id=CVE-2026-93290
  - https://www.cve.org/CVERecord?id=CVE-2026-93291
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Eufy Omni C20 and X10 Pro firmware to version 1.6.4 or later.
      owner: IT Operations
      addresses: CVE-2026-93289, CVE-2026-93290, CVE-2026-93291
      evidence: Eufy recommends users to upgrade to version 1.6.4 or later.
---

Eufy Omni C20 and Omni X10 Pro smart home devices contain multiple critical vulnerabilities that expose them to remote exploitation. These flaws include CVE-2026-93289, an OS command injection vulnerability during the device pairing process; CVE-2026-93290, which involves the use of hard-coded credentials that can be retrieved via log files; and CVE-2026-93291, a flaw involving improper certificate validation. 

These vulnerabilities collectively enable an unauthenticated, network-adjacent attacker to execute system-level commands, steal sensitive mapping data, or conduct man-in-the-middle attacks to achieve arbitrary code execution. Given that these devices are deployed globally in both home and IT environments, the potential impact includes unauthorized control over home automation hardware and potential pivot points into connected networks. Eufy has released firmware version 1.6.4 to address these security issues.

## Impact

The successful exploitation of these vulnerabilities can lead to full device compromise, allowing an attacker to execute arbitrary system-level commands, monitor sensitive user data such as home mapping logs, and perform man-in-the-middle interceptions. These devices are used globally, and if left unpatched, they pose a significant risk to the integrity and confidentiality of the home or office network segment where they reside.

## Recommendation

- Upgrade Eufy Omni C20 and Omni X10 Pro firmware to version 1.6.4 or later immediately.
- Isolate IoT devices on a dedicated, firewalled network segment separate from critical IT or business resources.
- Disable or restrict remote management and internet access for these devices unless explicitly required for operation.
- Implement VPN-only access for any necessary remote management tasks to reduce the attack surface.
