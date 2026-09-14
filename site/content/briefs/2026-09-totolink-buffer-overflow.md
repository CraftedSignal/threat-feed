---
title: Remote Buffer Overflow in Totolink A3002MU Router
slug: 2026-09-totolink-buffer-overflow
description: A critical buffer overflow vulnerability in the Totolink A3002MU router allows unauthenticated remote attackers to trigger memory corruption via the /boafrm/formFilter endpoint.
date: "2026-09-14T01:28:44Z"
lastmod: "2026-09-14T01:29:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:totolink:a3002mu_firmware:hh-b20211125.1046:*:*:*:*:*:*:*
vendors:
  - Totolink
products:
  - A3002MU (Hh-B20211125.1046)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Executing a manipulation of the argument ip6addr can lead to buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-90605
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90605
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90607
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90608
rules:
  - title: Detects CVE-2026-90607 Exploitation - Buffer Overflow via /boafrm/formNewSchedule
    description: Detects exploitation attempts against the formNewSchedule function by monitoring POST requests to the vulnerable path.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to web management interface
      owner: IT Operations
      due: 24h
      evidence: Exploit is public and vulnerability is remote
  mitigation_plan:
    - priority: immediate
      action: Disable external web management interface access
      owner: IT Operations
      addresses: CVE-2026-90605
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-14T01:28:56Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-90607 Exploitation - Buffer Overflow via /boafrm/formNewSchedule'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90607
  - at: "2026-09-14T01:29:02Z"
    level: L2
    summary: added coverage for A3002MU (Hh-B20211125.1046)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90608
---

A critical buffer overflow vulnerability (CVE-2026-90605) has been identified in the Totolink A3002MU router running firmware version Hh-B20211125.1046. The flaw exists within the 'formFilter' function of the 'boa' web server component. An unauthenticated remote attacker can exploit this vulnerability by sending a maliciously crafted HTTP request to the '/boafrm/formFilter' URI, specifically by manipulating the 'ip6addr' argument. Successful exploitation of this buffer overflow may result in arbitrary code execution or a denial of service condition. Given that exploit code for this vulnerability is publicly available, organizations using the affected router models face an immediate risk of compromise. Defenders should prioritize restricting access to the management interface and monitoring for anomalous HTTP traffic targeting the vulnerable endpoint.

## Impact

Successful exploitation of CVE-2026-90605 grants an attacker the ability to achieve remote code execution on the affected network device. This allows for complete compromise of the router, potentially enabling traffic interception, man-in-the-middle attacks, or persistent access to the internal network. The vulnerability poses a significant risk to consumer and small-office environments where this hardware is deployed.

## Recommendation

1. Block all external access to the web-based management interface of the Totolink A3002MU router at the firewall level.
2. Implement network segmentation to isolate vulnerable network hardware from critical business infrastructure.
3. Monitor ingress traffic to the '/boafrm/formFilter' endpoint for excessive payload lengths or suspicious characters within the 'ip6addr' argument.
