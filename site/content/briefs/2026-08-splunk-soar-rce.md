---
title: Arbitrary Code Execution in Splunk SOAR via Path Traversal
slug: 2026-08-splunk-soar-rce
description: Splunk SOAR versions prior to 8.6.0 are vulnerable to authenticated remote code execution due to improper path validation and insufficient role-based access control on the REST API.
date: "2026-08-19T22:43:10Z"
lastmod: "2026-08-20T13:11:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - splunk
vendors:
  - Splunk
products:
  - SOAR (8.5.0)
  - SOAR
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an authenticated user to submit a crafted file path to the REST API and execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-76357
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76357
  - https://help.splunk.com/en/splunk-soar/soar-on-premises/administer-soar-on-premises/8.5.0/manage-your-splunk-soar-on-premises-users-and-accounts/manage-roles-and-permissions-in-splunk-soar-on-premises
  - https://help.splunk.com/en/splunk-soar/soar-on-premises/administer-soar-on-premises/8.5.0/introduction-to-splunk-soar-on-premises/splunk-soar-on-premises-security-information
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2933
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Splunk SOAR to version 8.6.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76357 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Audit all user account roles and privileges within Splunk SOAR
      owner: SOC
      addresses: CVE-2026-76357
      evidence: Vulnerability relies on lack of role-based access control
updates:
  - at: "2026-08-20T13:11:33Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2933
---

Splunk SOAR versions below 8.6.0 contain a critical vulnerability identified as CVE-2026-76357, which allows authenticated users without assigned roles to achieve arbitrary code execution. The vulnerability is rooted in the REST API's failure to enforce role-based access controls for specific requests and a lack of input validation regarding file path parameters. An attacker can submit a crafted file path to the API, bypassing directory restrictions to execute arbitrary code on the underlying host. This vulnerability poses a significant risk to organizational environments relying on Splunk SOAR for security orchestration and response, as it enables unauthorized system-level operations by low-privileged authenticated accounts. Defenders should prioritize patching all Splunk SOAR instances to version 8.6.0 or higher.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary code with the privileges of the Splunk SOAR service account. This could lead to full compromise of the SOAR platform, lateral movement within the network, and the potential exfiltration or manipulation of sensitive security orchestration data. Organizations using Splunk SOAR for automated incident response are at high risk if default or low-privileged accounts are compromised.

## Recommendation

- Upgrade Splunk SOAR (On-premises) to version 8.6.0 or higher immediately.
- Review user accounts and role assignments within the Splunk SOAR platform to ensure the principle of least privilege is applied, specifically limiting access to REST API endpoints.
- Audit access logs for the SOAR REST API to identify anomalous requests involving directory traversal patterns (e.g., ../, .., or absolute file paths) originating from unprivileged or newly created service accounts.
