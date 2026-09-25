---
title: Information Disclosure and Account Hijacking in X-SpringBoot
slug: 2026-09-x-springboot-auth-bypass
description: The X-SpringBoot application up to version 6.0 contains an information disclosure vulnerability that allows unauthenticated attackers to retrieve login verification codes and hijack user accounts.
date: "2026-09-25T20:55:09Z"
lastmod: "2026-09-25T20:55:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:x-springboot:x-springboot:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve
vendors:
  - X-SpringBoot
products:
  - X-SpringBoot (<= 6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Attackers can request codes using known mobile numbers or email addresses, read them from responses, and authenticate as victims.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can authenticate as any user by submitting the public master code to the emailOrMobileLogin endpoint.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: X-SpringBoot through 6.0 ships with a hardcoded static master login verification code 172839 enabled by default in the database seed.
    confidence_band: high
cves:
  - id: CVE-2026-97063
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97063
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97064
rules:
  - title: Detect X-SpringBoot Verification Code Information Disclosure
    description: Detects potential exploitation of CVE-2026-97063 where unauthenticated requests to verification endpoints result in successful code disclosure.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-97064 Exploitation - Authentication Bypass via Master Code
    description: Detects exploitation attempts against CVE-2026-97064 where the hardcoded master code '172839' is used in the emailOrMobileLogin endpoint
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all internet-facing X-SpringBoot instances.
      owner: SOC
      due: 24h
      evidence: CVE-2026-97063 impacts X-SpringBoot versions up to 6.0.
  hunt_leads:
    - lead: Look for anomalous volume of GET requests to /sys/mobile/code or /sys/email/code.
      technique_id: T1110.001
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states these endpoints leak codes to unauthenticated users.
updates:
  - at: "2026-09-25T20:55:21Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-97064 Exploitation - Authentication Bypass via Master Code'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-97064
---

X-SpringBoot versions 6.0 and earlier contain a critical vulnerability where sensitive login verification codes are returned directly in the HTTP response body for unauthenticated API endpoints. Specifically, the endpoints '/sys/mobile/code' and '/sys/email/code' leak these codes without requiring authentication and without sending the codes to the intended account owners. An attacker can supply a target's mobile number or email address as a parameter to these endpoints and receive the valid verification code in the server response. With this code, the attacker can then authenticate as the victim via the '/sys/emailOrMobileLogin/login' endpoint. This flaw enables widespread account hijacking by bypassing standard MFA or verification workflows. Defenders should identify instances of X-SpringBoot 6.0 or lower and restrict access to these endpoints or upgrade to a patched version once available.

## Attack Chain

1. Attacker identifies a target mobile number or email address.
2. Attacker sends an unauthenticated HTTP GET request to /sys/mobile/code or /sys/email/code.
3. The vulnerable application processes the request and generates a verification code.
4. The application improperly embeds the code in the JSON response body sent to the client.
5. The attacker parses the HTTP response to extract the verification code.
6. The attacker submits the stolen code along with the target's identifier to /sys/emailOrMobileLogin/login.
7. The application validates the code, granting the attacker a session as the target user.
8. Attacker gains full unauthorized access to the victim's account.

## Impact

Successful exploitation allows unauthenticated attackers to hijack any account within an exposed X-SpringBoot instance. This could lead to full account takeover, unauthorized access to sensitive user data, and potential lateral movement if the hijacked accounts possess elevated privileges. Given the CVSS score of 9.1, the impact is severe, particularly for internet-facing installations.

## Recommendation

1. Identify and inventory all internet-facing instances of X-SpringBoot running version 6.0 or lower.
2. Implement strict network-level access control to block external access to the /sys/mobile/code and /sys/email/code endpoints until a patch is applied.
3. Deploy web application firewall (WAF) rules to inspect and alert on suspicious patterns of repeated requests to verification endpoints originating from single source IPs.
4. Monitor application logs for high volumes of 200 OK responses to /sys/mobile/code or /sys/email/code that are not followed by successful logins from the target user's known devices.
