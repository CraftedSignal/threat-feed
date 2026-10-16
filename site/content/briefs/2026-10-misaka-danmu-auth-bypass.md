---
title: Authentication Bypass in Misaka Danmu Server
slug: 2026-10-misaka-danmu-auth-bypass
description: Misaka Danmu Server versions 2.8.9 and earlier contain an authentication bypass vulnerability allowing unauthenticated attackers to modify sensitive configuration keys via the /api/ui/config-history/rollback endpoint.
date: "2026-10-16T18:44:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:misaka:danmu_server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application-vulnerability
  - misaka
vendors:
  - Misaka
products:
  - Danmu Server (<= 2.8.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Misaka Danmu Server through 2.8.9 contains an authentication bypass vulnerability that allows unauthenticated attackers to write arbitrary configuration keys.
    confidence_band: high
cves:
  - id: CVE-2026-111643
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111643
rules:
  - title: Detect CVE-2026-111643 Exploitation - Unauthorized Config Modification
    description: Detects unauthenticated POST requests to the rollback configuration endpoint that potentially indicate exploitation of CVE-2026-111643.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1565.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Misaka Danmu Server to a version beyond 2.8.9
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-111643
  mitigation_plan:
    - priority: immediate
      action: Upgrade Misaka Danmu Server to a version beyond 2.8.9
      owner: IT Operations
      addresses: CVE-2026-111643
      evidence: NVD vulnerability disclosure
---

Misaka Danmu Server versions 2.8.9 and earlier are affected by a critical authentication bypass vulnerability (CVE-2026-111643) originating in the /api/ui/config-history/rollback endpoint. This endpoint lacks proper authentication checks, allowing unauthenticated remote attackers to perform unauthorized configuration modifications. By sending a crafted POST request to this endpoint, an attacker can overwrite sensitive configuration keys such as 'ipWhitelist', 'trustedProxies', and 'webhookApiKey'. Successfully altering these keys permits the attacker to bypass access controls, effectively granting them administrative control over all protected API endpoints. Given the CVSS 3.1 base score of 9.8, this vulnerability poses a severe risk to service integrity and confidentiality.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative access to the Danmu Server installation. This impact enables attackers to exfiltrate sensitive data, manipulate system operations, or gain persistent access by modifying webhook configurations or trusted proxy settings, potentially leading to total system compromise in affected environments.

## Recommendation

* Immediately upgrade Misaka Danmu Server to a version beyond 2.8.9 to remediate the vulnerability.
* Audit logs for unauthorized POST requests directed at the /api/ui/config-history/rollback endpoint.
* Monitor changes to the 'ipWhitelist', 'trustedProxies', and 'webhookApiKey' configuration values within the application logs for any suspicious modifications.
