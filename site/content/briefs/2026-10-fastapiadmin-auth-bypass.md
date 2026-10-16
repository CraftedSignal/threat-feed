---
title: Authentication Bypass in FastapiAdmin
slug: 2026-10-fastapiadmin-auth-bypass
description: FastapiAdmin versions through 3.0 contain an authentication bypass vulnerability allowing unauthenticated attackers to obtain superuser sessions via unprotected auto-login endpoints.
date: "2026-10-16T18:44:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:fastapiadmin:fastapiadmin:*:*:*:*:*:*:*:*
vendors:
  - FastapiAdmin
products:
  - FastapiAdmin (<= 3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: FastapiAdmin through 3.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain sessions for any user by abusing unprotected auto-login endpoints.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: 'Use Alternate Authentication Material: Application Access Token'
    evidence: Attackers can list users via /api/v1/auth/auto-login/users, mint a superuser auto-login token, and exchange it for a JWT session.
    confidence_band: high
cves:
  - id: CVE-2026-111641
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111641
rules:
  - title: Detect CVE-2026-111641 Exploitation - Access to Auto-Login API
    description: Detects potential exploitation attempts of CVE-2026-111641 by flagging requests to the vulnerable auto-login enumeration endpoint.
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
    - Detection Engineering
  immediate_actions:
    - action: Restrict network access to /api/v1/auth/auto-login/ endpoints
      owner: IT Operations
      due: 24h
      evidence: Source confirms these endpoints are unprotected and enable authentication bypass.
  hunt_leads:
    - lead: Search logs for access to /api/v1/auth/auto-login/users
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this URI as the primary exploitation vector.
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to /api/v1/auth/auto-login/ at the WAF/Gateway layer
      owner: IT Operations
      addresses: CVE-2026-111641
      evidence: Vulnerability allows unauthenticated access to these endpoints.
---

FastapiAdmin through version 3.0 is affected by a critical authentication bypass vulnerability (CVE-2026-111641). The vulnerability exists within the application's auto-login functionality, which exposes administrative endpoints without proper authentication requirements. This allows an unauthenticated attacker to interact with the API to enumerate user accounts, generate valid auto-login tokens for arbitrary users, and subsequently exchange these tokens for valid JWT sessions. By targeting accounts with administrative privileges, an attacker can gain full control over the application environment. Given the nature of the vulnerability, which involves direct exploitation of exposed API endpoints, it poses a significant risk to the integrity and confidentiality of any deployment running version 3.0 or earlier. Organizations using FastapiAdmin should audit their API access logs for anomalous requests to the identified auto-login endpoints and restrict access to these paths at the network or reverse proxy level until a patch is applied.

## Impact

Successful exploitation grants an attacker full administrative access to the FastapiAdmin instance. This allows for the manipulation of application data, unauthorized access to underlying system configurations if the instance is improperly sandboxed, and potential exfiltration of sensitive information managed by the platform. The impact is critical, as it provides a trivial path to total application compromise without prior knowledge of credentials.

## Recommendation

* Restrict access to the path /api/v1/auth/auto-login/ at the reverse proxy or web application firewall level for all untrusted users.
* Audit web server logs for requests directed to /api/v1/auth/auto-login/users to identify potential scanning or exploitation attempts.
* Upgrade to a version of FastapiAdmin that mitigates CVE-2026-111641 as soon as a fix is released by the maintainers.
