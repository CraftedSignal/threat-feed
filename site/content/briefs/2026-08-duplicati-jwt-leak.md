---
title: Duplicati JWT Signing Key Exposure via Guard Bypass
slug: 2026-08-duplicati-jwt-leak
description: An unpatched vulnerability in Duplicati 2.2.0.3 allows authenticated attackers to bypass security guards and extract JWT signing keys to forge administrative tokens.
date: "2026-08-17T14:54:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - privilege-escalation
  - jwt
vendors:
  - Duplicati
products:
  - Duplicati (<= 2.2.0.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: With the extracted SigningKey, Authority and Audience, an attacker can forge a long-lived admin token that grants full administrative access to the application.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52646
  - https://github.com/duplicati/duplicati/pull/6787
rules:
  - title: Detect Potential Duplicati JWT Configuration Access Attempt
    description: Detects attempts to access the JWT configuration endpoint using non-lowercase variations to bypass security guards
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF/webserver filter rule for /api/v1/serversetting/JWTConfig
      owner: SOC
      due: 24h
      evidence: Exploit targets this specific path to leak sensitive keys
  mitigation_plan:
    - priority: immediate
      action: Upgrade Duplicati to version > 2.2.0.3
      owner: IT Operations
      addresses: Duplicati (<= 2.2.0.3)
      evidence: Fix provided in github.com/duplicati/duplicati/pull/6787
---

Researchers have disclosed a vulnerability in Duplicati 2.2.0.3 (and earlier versions) where a case-sensitive guard bypass in the settings API allows for the unauthorized retrieval of JWT configuration data. The application contains a protective mechanism intended to prevent access to the 'jwt-config' endpoint. However, by requesting the endpoint using PascalCase ('JWTConfig'), attackers can bypass this guard.

Successful exploitation grants an attacker the SigningKey, Authority, and Audience strings. Using this information, an attacker can construct and sign their own long-lived administrative JWTs. This enables the attacker to gain full administrative control over the Duplicati instance, including the ability to modify backup configurations and access protected data. This vulnerability was reported via responsible disclosure and is addressed in subsequent commits to the master branch.

## Attack Chain

1. Attacker establishes a valid, low-privileged session with the Duplicati web interface.
2. Attacker discovers that requests to /api/v1/serversetting/jwt-config are blocked by a security guard.
3. Attacker submits a request to /api/v1/serversetting/JWTConfig, successfully bypassing the case-sensitive filter.
4. The server returns a JSON response containing the SigningKey, Authority, and Audience values.
5. Attacker utilizes the extracted SigningKey to generate a new JSON Web Token (JWT) with elevated administrative claims.
6. Attacker replaces their existing session token with the forged administrative JWT.
7. Attacker accesses administrative endpoints, such as /api/v1/serversetting/AllowedHostnames, using the forged token to verify full privilege escalation.
8. Attacker proceeds to manage backups, export keys, or exfiltrate sensitive data via the administrative interface.

## Impact

Successful exploitation of this vulnerability results in full administrative compromise of the Duplicati server. This allows an attacker to manipulate backup tasks, steal backup data, and potentially execute further actions within the context of the host operating system, depending on the server's deployment and permissions.

## Recommendation

* Upgrade Duplicati instances to the latest available version beyond 2.2.0.3 immediately to patch the endpoint guard bypass.
* Monitor web server logs for requests to the /api/v1/serversetting/ endpoint containing non-standard case variations of 'jwt-config'.
* Implement strictly scoped network access controls to the Duplicati web interface to minimize exposure to untrusted users.
* Rotate the JWT SigningKey if there is any indication that the instance has been accessed by unauthorized parties.
