---
brief_id: brief-2026-10-29-powerjob-jwt-bypass
event_id: brief-2026-10-29-powerjob-jwt-bypass
revision: 1
activity_at: "2026-10-29T00:46:43Z"
title: 'PowerJob Server: Authentication Bypass and Token Forgery (CVE-2026-75431)'
slug: 2026-10-powerjob-jwt-bypass
description: PowerJob Server 5.1.2 uses a predictable algorithm to generate JWT signing keys, allowing unauthenticated attackers to forge tokens and achieve full administrative account takeover or OpenAPI authentication bypass.
date: "2026-10-29T00:46:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified technical mechanism against source documentation.
cpes:
  - cpe:2.3:a:powerjob:powerjob:5.1.2:*:*:*:*:*:*:*
vendors:
  - PowerJob
products:
  - PowerJob Server (5.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The JDBC URL is often publicly available in configuration files, therefore an attacker can autonomously calculate the signing key and forge JWT tokens.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.004
    technique_name: Private Keys
    evidence: Key signature (HS256) of PowerJob Server is formed by BASE64-decoding a hardcoded constant combined with the MD5 hash of the default JDBC URL.
    confidence_band: high
cves:
  - id: CVE-2026-75431
    cvss: 9.1
    epss: 0.01073
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-UNPREDICTABLE21-CVE-2026-75431_POWERJOB_JWT_KEY_PREDICTABLE
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75431
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-UNPREDICTABLE21-CVE-2026-75431_POWERJOB_JWT_KEY_PREDICTABLE&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all PowerJob Server instances and verify version is 5.1.2 or later patched release.
      owner: IT Operations
      due: 24h
      evidence: Source identifies version 5.1.2 as the affected product.
  hunt_leads:
    - lead: Search web server access logs for anomalous JWT usage or requests to the /namespace/list and OpenAPI endpoints that lack corresponding successful login events.
      technique_id: T1185
      data_needed:
        - Web server access logs
        - Application logs showing authentication events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Forged tokens bypass standard authentication processes, creating a mismatch in login audit logs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest patched version and rotate all administrative credentials and OpenAPI keys.
      owner: IT Operations
      addresses: CVE-2026-75431
      evidence: Source recommends randomizing the signing key and using separate keys for OpenAPI.
---

PowerJob Server version 5.1.2 contains a critical vulnerability (CVE-2026-75431) where the HS256 JWT signing key is deterministically derived from a hardcoded constant and the MD5 hash of the configured JDBC URL. Because the JDBC URL is typically exposed in default configuration files (e.g., application-daily.properties), an attacker can autonomously compute the signing key. Combined with the ability to compute or leak the required 'encryptedToken' for accounts, this allows for the forgery of valid JWTs for any user, including administrators, and the bypass of OpenAPI authentication.

## Attack Chain
1. Reconnaissance: Attacker identifies a target PowerJob Server instance exposed to the network.
2. Information Gathering: Attacker accesses the JDBC URL (typically via default config disclosure or other vulnerability) and identifies the system use of default credentials.
3. Key Derivation: Attacker performs local, offline computation: `key = BASE64(BASE_SECURITY + MD5(JDBC_URL))`.
4. Credential Computation: For default installations, attacker computes the `encryptedToken` for the admin user using the known default password.
5. Token Forgery: Attacker signs a malicious JWT using the derived key and the computed `encryptedToken`.
6. Exploitation: Attacker submits the forged JWT to the PowerJob web console or OpenAPI endpoints, successfully bypassing authentication to gain full administrative access.

## Impact
Successful exploitation results in full administrative control over the PowerJob Server, including the ability to manage tasks, view sensitive business data, and execute operations via the OpenAPI. The vulnerability is considered critical as it allows for autonomous token forgery without requiring existing session tokens or active credentials.

## Recommendation
- Upgrade PowerJob Server to a version where the JWT signing key is randomly generated and persisted, rather than derived from environment properties.
- Audit all publicly accessible configuration files and backup locations to ensure JDBC URLs and other sensitive environment properties are not exposed.
- Enforce secondary authentication and rotation policies for all administrative and OpenAPI service accounts.
- Restrict access to the PowerJob web console and OpenAPI endpoints to trusted management networks.
