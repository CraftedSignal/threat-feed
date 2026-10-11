---
title: Authentication Bypass in AmoyLab Unla
slug: 2026-10-amoylab-unla-auth-bypass
description: AmoyLab Unla versions 0.10.0 and earlier are vulnerable to an authentication bypass in the OAuth2 implementation that permits unauthenticated attackers to obtain valid access tokens and interact with restricted APIs.
date: "2026-10-11T16:03:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:amoylab:unla:*:*:*:*:*:*:*:*
vendors:
  - AmoyLab
products:
  - Unla (<= 0.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AmoyLab Unla through 0.10.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain valid access tokens
    confidence_band: high
cves:
  - id: CVE-2026-108865
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108865
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all servers running AmoyLab Unla and prepare for emergency patching
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108865
  mitigation_plan:
    - priority: immediate
      action: Upgrade AmoyLab Unla to the latest version beyond 0.10.0
      owner: IT Operations
      addresses: CVE-2026-108865
      evidence: Source NVD disclosure
---

AmoyLab Unla, an OAuth2 server implementation, contains a critical authentication bypass vulnerability (CVE-2026-108865) affecting versions 0.10.0 and earlier. The security flaw stems from the server's failure to properly authenticate the resource owner during the OAuth2 authorization flow. This defect allows unauthenticated attackers to register their own client, initiate an authorization request, and successfully exchange it for valid access tokens via the /token endpoint. 

Successful exploitation enables an attacker to gain unauthorized access to OAuth2-protected Model Context Protocol (MCP) prefixes and proxied upstream APIs. Furthermore, attackers can gain access to credentials injected into these proxied services. Given the nature of the vulnerability as an authentication bypass, it represents a significant risk for organizations relying on Unla for identity mediation or API protection, as it effectively nullifies the expected security boundary for downstream services.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to bypass authentication controls and interact with protected internal resources. Impacted organizations face potential data exfiltration from proxied upstream APIs, unauthorized use of injected credentials, and total compromise of restricted MCP prefixes. The CVSS 3.1 score of 8.2 reflects the high potential for impact on confidentiality and integrity within integrated service environments.

## Recommendation

* Prioritize the identification of all instances of AmoyLab Unla within the environment to determine exposure.
* Monitor access logs for suspicious OAuth2 client registration activity followed by rapid requests to the /authorize and /token endpoints from unidentified or unauthorized sources.
* Update all instances of AmoyLab Unla to a patched version beyond 0.10.0 once available.
* Implement additional API gateway-level authentication checks for services proxied behind Unla as a temporary compensatory control until patching can be completed.
