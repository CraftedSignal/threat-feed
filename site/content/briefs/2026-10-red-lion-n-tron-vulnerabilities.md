---
title: Multiple Vulnerabilities in Red Lion Controls N-Tron 700 Series
slug: 2026-10-red-lion-n-tron-vulnerabilities
description: Multiple high and critical severity vulnerabilities in Red Lion Controls N-Tron 700 series switches, including hard-coded credentials and improper authentication, allow for unauthorized administrative access, configuration theft, and denial-of-service.
date: "2026-10-08T17:06:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - industrial-control-systems
  - ot-security
  - vulnerability-management
vendors:
  - Red Lion Controls
products:
  - N-Tron 700 Series (<=Firmware_3.11.0)
  - N-Tron 700 Series (<=Bootloader_2.0.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Default factory credentials with administrative access are enabled and persist even after configuring other administrator accounts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Usernames and passwords, including the default factory credentials, are stored in plaintext within the configuration file.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Further, a malicious user can cause the switch to reboot by navigating to a specific URL on the device.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01
  - https://www.cve.org/CVERecord?id=CVE-2026-32645
  - https://www.cve.org/CVERecord?id=CVE-2026-39460
  - https://www.cve.org/CVERecord?id=CVE-2026-28745
  - https://www.cve.org/CVERecord?id=CVE-2026-33367
  - https://www.cve.org/CVERecord?id=CVE-2026-29797
  - https://www.cve.org/CVERecord?id=CVE-2026-39453
  - https://www.cve.org/CVERecord?id=CVE-2026-33272
action_plan:
  priority: elevated
  owners:
    - OT Security
    - Network Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade N-Tron 700 Series firmware to 3.11.1 or later.
      owner: OT Security
      addresses: All listed CVEs
      evidence: 'Vendor fix: Red Lion controls recommends the following upgrades for the N-Tron 700 Series'
---

Red Lion Controls N-Tron 700 series industrial switches are affected by a suite of seven vulnerabilities (CVE-2026-32645, CVE-2026-39460, CVE-2026-28745, CVE-2026-33367, CVE-2026-29797, CVE-2026-39453, CVE-2026-33272) that compromise the integrity and availability of the devices. These flaws range from hard-coded factory credentials to improper storage of plaintext passwords in configuration files and missing authentication for critical functions such as TFTP transfers initiated via SNMP. An attacker can leverage these weaknesses to gain full administrative control over the switch, modify configuration files, or induce continuous reboots by navigating to specific URLs on the device. Given their deployment in critical infrastructure, including communication and manufacturing sectors, these vulnerabilities present a significant risk of lateral movement, network disruption, and credential exfiltration.

## Impact

Successful exploitation grants unauthorized administrative access, enabling adversaries to extract sensitive network configuration credentials stored in plaintext or weakly encrypted formats. Furthermore, the ability to trigger a continuous reboot condition leads to persistent denial-of-service, disrupting critical communication flows. The vulnerability affects N-Tron 700 series switches globally across commercial facilities, IT, and manufacturing environments.

## Recommendation

Prioritize the following actions to mitigate the risk of exploitation:

- Upgrade N-Tron 700 Series firmware to version 3.11.1 or greater immediately to remediate the vulnerabilities listed in ICSA-26-281-01.
- Disable access to the web GUI on all N-Tron 700 Series devices to prevent unauthorized configuration access and DoS URL exploitation.
- Disable or restrict access to SNMP communities, particularly those allowing unauthenticated command execution or TFTP initialization.
- Implement network segmentation to isolate industrial switch management interfaces from broader organizational networks.
