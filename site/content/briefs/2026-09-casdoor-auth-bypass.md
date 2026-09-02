---
title: Authentication Bypass in Casdoor Upload Resource API
slug: 2026-09-casdoor-auth-bypass
description: Casdoor versions up to 4.0.0 contain an authentication bypass vulnerability in the upload-resource API that permits remote, unauthenticated file operations.
date: "2026-09-02T01:10:40Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:casdoor:casdoor:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - webserver
vendors:
  - Casdoor
products:
  - Casdoor (<= 4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-84423
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84423
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Casdoor API endpoints to known-good IP ranges
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated access
  hunt_leads:
    - lead: Unauthorized POST requests to API endpoints managing resource uploads
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is in controllers/resource.go upload-resource API
  mitigation_plan:
    - priority: immediate
      action: Disable upload-resource API functionality if not required for business operations
      owner: IT Operations
      addresses: CVE-2026-84423
      evidence: Vulnerability affects the upload-resource API component
---

Casdoor versions up to 4.0.0 are vulnerable to an authentication bypass vulnerability within the upload-resource API component, specifically located in the controllers/resource.go file. This flaw stems from missing authentication checks, which allows remote, unauthenticated attackers to interact with the API. The vulnerability poses a significant risk as it provides a mechanism for unauthorized file operations, potentially leading to unauthorized data exposure or malicious file uploads. Public exploit material exists for this vulnerability. Security researchers reported that the vendor removed the associated issue tracking the bug from GitHub without explanation and failed to respond to private disclosure attempts, indicating a lack of forthcoming vendor patches or guidance. Organizations using Casdoor should immediately evaluate exposure of the affected API endpoint and implement compensatory network controls to restrict access.

## Impact

Successful exploitation allows an unauthenticated remote attacker to bypass intended access controls within the Casdoor resource management module. This unauthorized access can lead to the manipulation of resources, arbitrary file uploads, or exfiltration of sensitive information depending on the scope of the API's functionality. Given the lack of a vendor-provided patch, deployments are at risk of active exploitation by threat actors leveraging the publicly available exploit code.

## Recommendation

- Implement strict network-level access control lists (ACLs) to restrict access to the Casdoor API endpoints to trusted administrative IP ranges.
- Monitor web server access logs for anomalous POST requests directed at the resource upload API paths, specifically investigating any requests originating from untrusted or non-authenticated sessions.
- If the functionality is not business-critical, disable the resource upload API until the vendor provides a remediation or security update.
