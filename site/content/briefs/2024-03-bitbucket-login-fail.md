---
title: Bitbucket User Login Failure Detection
slug: 2024-03-bitbucket-login-fail
description: Detection of Bitbucket user login failures, potentially indicating credential access attempts, initial access attempts, or other malicious activity.
date: "2024-03-08T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - bitbucket
  - authentication
  - brute-force
  - credential-access
  - initial-access
vendors:
  - Atlassian
products:
  - Bitbucket
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_detected.yml
rules:
  - title: Bitbucket User Login Failure
    description: Detects user authentication failure events in Bitbucket audit logs.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - initial-access
    techniques:
      - T1078.004
      - T1110
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Multiple User Login Failures from Single IP
    description: Detects multiple user login failures from a single IP address within a short timeframe, which may indicate a brute-force attack.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - initial-access
    techniques:
      - T1078.004
      - T1110
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

This threat brief focuses on detecting user login failures within Bitbucket environments. Monitoring failed login attempts is crucial as it can indicate various malicious activities, including credential stuffing, brute-force attacks, or attempts to gain unauthorized initial access. The audit logs in Bitbucket record details of these authentication failures, providing valuable data for security monitoring. The rule provided detects these events and can be used for correlation with other security events based on the "author.name" field for enhanced accuracy and context. Requires "Advance" log level to receive audit events.

## Attack Chain

1. **Initial Access Attempt:** An attacker attempts to gain initial access to a Bitbucket account using a compromised or guessed username.
2. **Credential Guessing:** The attacker attempts to guess the user's password through manual attempts or automated tools.
3. **Authentication Failure:** Bitbucket records a "User login failed" event due to incorrect credentials. The `auditType.category` is Authentication, and `auditType.action` is User login failed.
4. **Multiple Failed Attempts:** The attacker repeats the login attempts with different password variations or using a list of compromised credentials.
5. **Account Lockout (Optional):** Depending on Bitbucket's configuration, repeated failed login attempts may trigger an account lockout.
6. **Successful Login (Potential):** After multiple attempts, the attacker may eventually guess the correct password or use a valid compromised credential.
7. **Privilege Escalation/Persistence (If Successful):** If successful, the attacker could escalate privileges, establish persistence, or perform other malicious actions within the Bitbucket environment.

## Impact

Successful exploitation can lead to unauthorized access to sensitive code repositories, intellectual property theft, and potential supply chain compromise. Attackers could inject malicious code, modify existing code, or exfiltrate sensitive data. Detecting these failed login attempts early can prevent significant damage. Although the number of victims cannot be determined with this specific detection, a successful attack can have far-reaching impacts.

## Recommendation

*   Deploy the Sigma rule "Bitbucket User Login Failure" to your SIEM to detect suspicious authentication failures (logsource: bitbucket, service: audit). Tune for your environment by correlating on the author.name field.
*   Investigate the source IP addresses associated with the failed login attempts to identify potential malicious actors.
*   Implement multi-factor authentication (MFA) to significantly reduce the risk of successful credential-based attacks.
*   Monitor for unusual activity following any successful login after a series of failures.
*   Enforce strong password policies to reduce the effectiveness of brute-force attacks.
