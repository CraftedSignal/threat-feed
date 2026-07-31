---
title: NocoBase Authenticated SQL Injection to RCE
slug: 2026-07-nocobase-sql-rce
description: A critical SQL injection vulnerability in NocoBase allows authenticated attackers to achieve remote code execution on the underlying PostgreSQL container via stacked statements.
date: "2026-07-31T19:45:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - webserver
  - sql-injection
  - rce
  - authentication-bypass
vendors:
  - NocoBase
products:
  - NocoBase server
  - '@nocobase/plugin-notification-in-app-message'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated visitor to sign up and then exploit the SQL injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Stacked-statement COPY ... TO PROGRAM runs shell commands as uid=999(postgres) inside the database container.
    confidence_band: high
cves:
  - id: CVE-2026-52887
    cvss: 10
    epss: 0.00593
references:
  - https://github.com/advisories/GHSA-p849-8hwh-84j9
  - CVE-2026-52887
rules:
  - title: Detect NocoBase CVE-2026-52887 Exploitation Attempt
    description: Detects exploitation attempts against CVE-2026-52887 by identifying suspicious SQL syntax within the filter query parameter of the myInAppChannels endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

NocoBase versions 2.0.60 and earlier contain a critical SQL injection vulnerability in the `/api/myInAppChannels:list` endpoint. The vulnerability arises because the `latestMsgReceiveTimestamp` filter parameter is unsafely interpolated into a `Sequelize.literal()` template string without proper escaping or parameter binding. Because NocoBase defaults to allowing anonymous account registration (`allowSignUp: true`), any unauthenticated attacker can create an account and access this endpoint. 

The application utilizes the `pg` driver, which supports stacked SQL statements. Coupled with the default PostgreSQL container configuration where the `nocobase` database user is granted superuser privileges (`rolsuper=true`), an attacker can execute arbitrary system commands using the `COPY ... TO PROGRAM` syntax. This vulnerability leads to full database compromise, including sensitive data exfiltration (such as administrator password hashes) and remote code execution within the database container.

## Attack Chain

1. Attacker interacts with the `/api/auth:signUp` endpoint to create a new user account, exploiting the default `allowSignUp: true` configuration.
2. Attacker performs an authentication request to `/api/auth:signIn` to obtain a valid `member` role JSON Web Token (JWT).
3. Attacker identifies the vulnerable `filter[latestMsgReceiveTimestamp][$lt]` parameter on the `/api/myInAppChannels:list` endpoint.
4. Attacker validates the injection point using a time-based oracle payload (e.g., `PG_SLEEP(5)`).
5. Attacker crafts a malicious HTTP GET request containing a stacked-statement SQL payload using `COPY ... TO PROGRAM`.
6. The backend database executes the injected command with the privileges of the `postgres` system user (uid 999).
7. Attacker achieves command execution and can exfiltrate sensitive collections or system data from the host container.

## Impact

Successful exploitation allows unauthenticated attackers to gain full access to the NocoBase database. The impact includes the exfiltration of sensitive information, such as administrator credentials (stored as PBKDF2 hashes), and remote code execution within the database container, which may facilitate lateral movement or further environment compromise.

## Recommendation

- Upgrade NocoBase to version 2.0.61 or later immediately.
- Disable anonymous sign-ups by modifying the `auth-basic` configuration if registration is not required.
- Review database role privileges and ensure the PostgreSQL user configured for NocoBase follows the principle of least privilege rather than running as a superuser.
- Deploy the provided Sigma rule to detect anomalous requests to the `/api/myInAppChannels:list` endpoint.
