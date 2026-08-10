---
title: Remote Permission Bypass in Uasoft Badaso File API
slug: 2026-08-10-badaso-permission-bypass
description: A publicly disclosed vulnerability in Uasoft Badaso 3.0.0-alpha allows remote attackers to bypass permission controls within the File API component.
date: "2026-08-10T01:49:42Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Uasoft
products:
  - Badaso (3.0.0-alpha)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation leads to permission issues.
    confidence_band: high
cves:
  - id: CVE-2026-19376
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19376
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internet-facing instances of Uasoft Badaso to identify 3.0.0-alpha deployments.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Uasoft Badaso 3.0.0-alpha.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the Badaso File API routes at the network edge.
      owner: IT Operations
      addresses: CVE-2026-19376
      evidence: Vulnerability allows remote exploitation via API routes.
---

A vulnerability (CVE-2026-19376) has been identified in Uasoft Badaso version 3.0.0-alpha, specifically affecting the ApiRequest class located in src/Routes/api.php within the File API component. This vulnerability stems from improper permission handling, which can be triggered remotely by an unauthenticated attacker. The flaw has been publicly disclosed, and the project maintainers have not yet provided a patch or formal response to the reported issue. Given the public availability of the vulnerability details and the lack of a fix, defenders should monitor for unauthorized access attempts directed at the File API endpoints.

## Impact

Successful exploitation allows remote attackers to manipulate requests to the File API, leading to a bypass of intended permission controls. This can result in unauthorized access to sensitive files or administrative functions governed by the File API. As of the current reporting, no remediation is available from the vendor, placing all deployments of Badaso 3.0.0-alpha at risk of unauthorized access.

## Recommendation

- Perform an inventory of all internet-facing instances of Uasoft Badaso to identify version 3.0.0-alpha.
- Implement restrictive access controls at the network perimeter (WAF or firewall) for all traffic targeting API endpoints associated with Badaso's File API until a vendor patch is released.
- Audit web server access logs for anomalous POST or GET requests to the File API routes identified in the vulnerability report.
