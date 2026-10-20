---
brief_id: brief-2026-10-draytek-command-injection
event_id: brief-2026-10-draytek-command-injection
revision: 1
activity_at: "2026-10-20T13:08:01Z"
title: 'DrayTek Vigor2960: Command injection in CGI Process (CVE-2026-113389)'
slug: 2026-10-draytek-command-injection
description: DrayTek Vigor2960 firmware version 1.5.1.6 Revision 8218 is vulnerable to unauthenticated remote command injection via the set_table function in mainfunction.cgi.
date: "2026-10-20T13:08:01Z"
lastmod: "2026-10-20T14:17:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Matches NVD source content
cpes:
  - cpe:2.3:h:draytek:vigor2960:1.5.1.6:*:*:*:*:*:*:*
tags:
  - network-device
  - command-injection
  - vulnerability
  - cve-2026-113389
  - cve-2026-113390
  - remote-code-execution
  - network-infrastructure
vendors:
  - DrayTek
products:
  - Vigor2960 (1.5.1.6 Revision 8218)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument sectiontype results in command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument sectiontype results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-113389
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-113390
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113389
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113390
rules:
  - title: Detects CVE-2026-113389 Exploitation - Remote Command Injection in Vigor2960
    description: Detects exploitation attempts against CVE-2026-113389 by identifying shell metacharacters in the sectiontype argument of mainfunction.cgi
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade DrayTek Vigor2960 to 1.5.1.7
      owner: IT Operations
      due: 24h
      evidence: 'The vendor explains: 2960 1.5.1.7 has corrected many security issues.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to 1.5.1.7 or replace EoS hardware
      owner: IT Operations
      addresses: CVE-2026-113389
      evidence: Product is EoS with limited support
updates:
  - at: "2026-10-20T14:17:09Z"
    level: L2
    summary: added coverage for Vigor2960 (1.5.1.6 Revision 8218)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-113390
---

DrayTek Vigor2960 firmware version 1.5.1.6 Revision 8218 contains a critical command injection vulnerability (CVE-2026-113389) residing within the set_table function of the /cgi-bin/mainfunction.cgi script. An unauthenticated remote attacker can exploit this flaw by manipulating the sectiontype argument, leading to arbitrary command execution on the affected network device. The vendor has identified this issue and released firmware version 1.5.1.7. However, the Vigor2960 product line has reached End-of-Life (EoS) status, meaning manufacturer support is extremely limited, and security updates are only provided for critical, unauthenticated vulnerabilities. The vulnerability is publicly disclosed, necessitating immediate action for administrators operating this hardware.

## Impact

Successful exploitation allows for full remote system compromise, enabling attackers to gain unauthorized access to internal network traffic, modify device configurations, or leverage the router as a pivot point for lateral movement into protected internal segments. Given that the Vigor2960 is an edge device, the risk of perimeter breach is high.

## Recommendation

* Patch affected Vigor2960 devices to firmware version 1.5.1.7 immediately.
* Evaluate the retirement of Vigor2960 devices from the network infrastructure due to EoS status and limited security support.
* Monitor webserver access logs for anomalous POST requests directed at /cgi-bin/mainfunction.cgi that include shell metacharacters in the sectiontype query parameter.
* Restrict management interface access to trusted internal IP addresses only.
