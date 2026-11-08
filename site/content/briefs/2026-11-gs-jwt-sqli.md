---
brief_id: brief-2026-11-08-gs-jwt-sqli
event_id: brief-2026-11-08-gs-jwt-sqli
revision: 1
activity_at: "2026-11-08T14:45:35Z"
title: 'GS JWT: Unauthenticated SQL injection and admin JWT forgery (CVE-2026-113615)'
slug: 2026-11-gs-jwt-sqli
description: An unauthenticated SQL injection vulnerability in the GS JWT WordPress plugin allows attackers to forge administrator JWTs and create persistent administrative accounts.
date: "2026-11-08T14:45:35Z"
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
cpes:
  - cpe:2.3:a:gs_jwt_project:gs_jwt:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sqli
  - jwt
  - authentication-bypass
  - remote-code-execution
products:
  - GS JWT (WordPress plugin)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated SQL injection on POST /wp-json/gs-jwt/v1/verify-otp forges a server-signed JWT.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: Local Account
    evidence: Optional create_admin=true adds a persistent administrator via REST.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: forges a server-signed JWT. Registers an HTTP session with Authorization Bearer.
    confidence_band: high
cves:
  - id: CVE-2026-113615
    cvss: 9.8
    epss: 0.00533
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113615
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-GS_JWT_CVE_2026_113615_SQLI
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-GS_JWT_CVE_2026_113615_SQLI&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-113615 exploitation attempt
    description: Detects unauthorized access attempts to the GS JWT OTP verification endpoint associated with CVE-2026-113615
    platform: sigma
    severity: high
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
    - action: Inventory all WordPress sites to identify the GS JWT plugin.
      owner: IT Operations
      due: 24h
      evidence: Plugin is the target of CVE-2026-113615.
    - action: Deploy WAF or web server rules to monitor or block requests to /wp-json/gs-jwt/v1/verify-otp.
      owner: SOC
      due: 24h
      evidence: Exploitation occurs via this specific path.
  hunt_leads:
    - lead: Search WordPress audit logs or database for new administrator account creation timestamps correlating with plugin traffic.
      technique_id: T1136.001
      data_needed:
        - WordPress audit logs
        - Database user table modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit supports creating a new persistent administrator via REST.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the GS JWT plugin until a verified patch is installed.
      owner: IT Operations
      addresses: CVE-2026-113615
      evidence: Plugin vulnerability leads to full admin compromise.
---

CVE-2026-113615 is a critical SQL injection vulnerability in the GS JWT WordPress plugin. An unauthenticated attacker can exploit this via the `/wp-json/gs-jwt/v1/verify-otp` endpoint to forge a server-signed JSON Web Token (JWT). This token grants the attacker administrative privileges, enabling them to register new, persistent administrator accounts via the WordPress REST API. Publicly available exploit modules confirm the ease of exploitation.

## Attack Chain

1. Attacker identifies a target running the vulnerable GS JWT plugin.
2. Attacker sends a malicious POST request to the `/wp-json/gs-jwt/v1/verify-otp` endpoint.
3. SQL injection payload is processed by the plugin to forge a valid administrator JWT.
4. Attacker receives the forged JWT and uses it in an `Authorization: Bearer` header.
5. Attacker authenticates to the WordPress REST API as an administrator.
6. Attacker optionally invokes the `/wp/v2/users` endpoint to create a new persistent administrator account.

## Impact

Successful exploitation results in full administrative control over the WordPress instance. This includes the ability to modify site content, install malicious plugins, exfiltrate data, and create persistent backdoors via new administrative users.

## Recommendation

- Immediately audit WordPress installations for the presence of the GS JWT plugin.
- Update the GS JWT plugin to a patched version if available; otherwise, disable or remove the plugin until a patch is applied.
- Review WordPress user lists for unauthorized administrative accounts created or modified since the vulnerability's discovery.
- Implement strict rate-limiting on the `/wp-json/gs-jwt/v1/verify-otp` endpoint to mitigate automated exploitation attempts.
