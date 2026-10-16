---
title: Authentication Bypass via Hardcoded HMAC Secret in DataBuff ai-apm-web
slug: 2026-10-databuff-auth-bypass
description: An unauthenticated authentication bypass vulnerability (CVE-2026-111692) in DataBuff ai-apm-web allows attackers to forge administrative session tokens using a hardcoded HMAC secret.
date: "2026-10-16T18:45:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:databuff:ai-apm-web:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - jwt
  - web-application
  - cve-2026-111692
vendors:
  - DataBuff
products:
  - ai-apm-web (<= 0.1.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: Attacker can forge admin session tokens to gain full administrative access.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: The vulnerability is caused by a hardcoded HMAC secret in JwtTokenService.
    confidence_band: high
cves:
  - id: CVE-2026-111692
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111692
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch ai-apm-web to the latest version to remove hardcoded secrets.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111692
  hunt_leads:
    - lead: Unauthorized access attempts or successful logins to /webapi routes.
      technique_id: T1185
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated attacker can forge admin session tokens to gain full administrative access.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to /webapi routes.
      owner: Network Security
      addresses: CVE-2026-111692
      evidence: Authentication bypass allows access to /webapi routes.
---

DataBuff ai-apm-web versions 0.1.10 and earlier contain a critical authentication bypass vulnerability (CVE-2026-111692) rooted in the JwtTokenService component. The service utilizes a hardcoded HMAC secret, referred to as 'dev-secret', to sign JSON Web Tokens (JWT). An unauthenticated attacker can leverage this static secret to craft and sign arbitrary session tokens. By setting the token payload to include administrative privileges and a future expiration timestamp, an attacker can bypass all authentication checks. This grants the attacker full administrative access to protected /webapi endpoints, including the Doris SQL query API, facilitating potential unauthorized data access, modification, or further system compromise. The vulnerability is highly severe (CVSS 9.8) because it requires no prior authentication or specialized knowledge of the target environment.

## Attack Chain

1. Attacker performs reconnaissance to identify DataBuff ai-apm-web deployments via public-facing services.
2. Attacker interacts with the target /webapi routes to confirm application presence.
3. Attacker retrieves the publicly available source code or identifies the hardcoded 'dev-secret' from the JwtTokenService implementation.
4. Attacker constructs a malicious JWT payload containing 'admin' claims and an extended expiration date.
5. Attacker signs the malicious JWT using the identified 'dev-secret' HMAC key.
6. Attacker submits the forged JWT in the 'Authorization' header of HTTP requests directed at protected /webapi endpoints.
7. DataBuff server validates the forged signature, incorrectly authenticating the request.
8. Attacker gains full administrative control over the application, including the ability to execute arbitrary queries against the Doris SQL API.

## Impact

Successful exploitation results in full administrative access to the ai-apm-web application. Impacted organizations face risks of data exfiltration from the underlying Doris SQL database, unauthorized modification of application settings, and potential secondary exploitation of the host environment. This vulnerability affects all DataBuff ai-apm-web users running version 0.1.10 or earlier.

## Recommendation

* Patch ai-apm-web to a version containing a remediated, non-hardcoded authentication secret immediately.
* Audit logs for suspicious administrative activity originating from anomalous IP addresses or unexpected sessions using forged JWT signatures.
* Restrict network access to the /webapi routes to authorized subnets to mitigate exposure to unauthenticated external actors.
* Implement centralized monitoring for the Doris SQL query API to detect and block unauthorized query patterns.
