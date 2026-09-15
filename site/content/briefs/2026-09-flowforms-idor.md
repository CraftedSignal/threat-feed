---
title: Authenticated IDOR Vulnerability in FlowForms
slug: 2026-09-flowforms-idor
description: An authenticated Insecure Direct Object Reference (IDOR) vulnerability in FlowForms version 1.1.1 and earlier allows attackers with contributor-level access to modify arbitrary forms.
date: "2026-09-15T06:27:09Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:flowforms:flowforms:*:*:*:*:*:*:*:*
tags:
  - idor
  - web-vulnerability
  - flowforms
  - cve-2026-12400
vendors:
  - FlowForms
products:
  - FlowForms (<= 1.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated IDOR in FlowForms allows unauthorized modification of arbitrary forms.
    confidence_band: high
cves:
  - id: CVE-2026-12400
    cvss: 4.3
    epss: 0.00371
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0X00PHANTOM-HAT-CVE-2026-12400-EXPLOIT
rules:
  - title: Detects CVE-2026-12400 Exploitation - Unauthorized Form Modification
    description: Detects suspicious modifications to FlowForms via the REST API endpoint by checking for authenticated requests to form IDs that might indicate IDOR attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch FlowForms to latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-12400 remediation
  enrichment_needed:
    - item: Exploitation in-the-wild telemetry
      owner: CTI
      reason: Assess urgency of patch deployment
      evidence: Source lacks real-world incident data
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version > 1.1.1
      owner: IT Operations
      addresses: CVE-2026-12400
      evidence: Source documentation for CVE-2026-12400
---

FlowForms versions 1.1.1 and earlier contain an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-12400) within the REST API endpoint responsible for form management. The vulnerability resides in the path /flowforms/v1/forms/{id}, where the system fails to adequately validate the authorization level of the requesting user against the requested form ID. An attacker with a low-privileged account, such as a contributor, can manipulate the ID parameter in the request to modify forms they are not authorized to access or manage. A proof-of-concept exploit is publicly available, increasing the likelihood of exploitation by actors seeking to alter form content or disrupt organizational workflows. 

## Impact

Successful exploitation allows an authenticated user to perform unauthorized modifications to forms within the FlowForms application. This can lead to data integrity issues, unauthorized data collection via modified input fields, or workflow disruption. The impact is limited to the application scope, but poses a significant risk to organizations relying on FlowForms for internal or public-facing data collection.

## Recommendation

- Upgrade FlowForms to a version beyond 1.1.1 immediately to remediate CVE-2026-12400.
- Review user permission assignments to ensure that accounts with contributor-level access are strictly limited to necessary form modification scopes.
- Audit web server access logs for anomalous patterns of repeated POST or PUT requests to the /flowforms/v1/forms/ endpoint originating from low-privileged user accounts.
