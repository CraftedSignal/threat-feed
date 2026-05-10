---
title: Sentry 8.2.0 Remote Code Execution via Pickle Deserialization (CVE-2021-47935)
slug: 2026-05-sentry-rce
description: Sentry 8.2.0 contains a remote code execution vulnerability (CVE-2021-47935) that allows authenticated superusers to execute arbitrary commands by injecting malicious pickle-serialized objects through the audit log entry data parameter via crafted POST requests to the admin audit log endpoint.
date: "2026-05-10T13:20:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - pickle
  - deserialization
  - sentry
vendors:
  - Sentry
products:
  - Sentry 8.2.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2021-47935
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47935
  - https://sentry.io/welcome/
  - https://www.exploit-db.com/exploits/50318
  - https://www.vulncheck.com/advisories/sentry-remote-code-execution-via-pickle-deserialization
rules:
  - title: Detect Suspicious Sentry Pickle Deserialization in Audit Log
    description: Detects CVE-2021-47935 exploitation — POST requests to the Sentry audit log endpoint with base64-encoded data, indicating potential pickle deserialization attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
  - title: Detect Sentry Admin Audit Log Access
    description: Detects access to the Sentry admin audit log endpoint, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Sentry 8.2.0 is vulnerable to remote code execution (CVE-2021-47935) due to insecure deserialization of pickle objects. This vulnerability allows authenticated superusers to execute arbitrary commands on the Sentry server. An attacker with superuser privileges can inject malicious pickle-serialized objects through the audit log entry `data` parameter. The vulnerability arises because the application fails to properly sanitize or validate the data being deserialized, allowing an attacker to inject arbitrary Python code within a base64-encoded compressed pickle payload. Exploitation requires authentication as a superuser, limiting the scope to compromised or malicious administrators.

## Attack Chain

1. An attacker authenticates to the Sentry application as a superuser.
2. The attacker crafts a malicious pickle payload containing arbitrary Python code for execution.
3. The pickle payload is compressed and then base64 encoded.
4. The attacker crafts a POST request to the `/admin/auditlog/` endpoint.
5. The POST request includes the base64-encoded compressed pickle payload within the `data` parameter of the audit log entry.
6. The Sentry application receives the POST request and attempts to deserialize the pickle data without proper sanitization.
7. The malicious pickle payload is deserialized, leading to arbitrary code execution with the privileges of the Sentry application.
8. The attacker achieves remote code execution on the Sentry server.

## Impact

Successful exploitation allows an attacker to execute arbitrary commands on the Sentry server with the privileges of the application. This can lead to complete compromise of the Sentry instance, including access to sensitive data, modification of configurations, and potential lateral movement to other systems within the network. Given the critical role Sentry often plays in application monitoring and incident response, a successful attack could severely impact an organization's security posture.

## Recommendation

*   Upgrade Sentry to a patched version that addresses CVE-2021-47935.
*   Deploy the Sigma rule `Detect Suspicious Sentry Pickle Deserialization in Audit Log` to monitor for exploitation attempts targeting the `/admin/auditlog/` endpoint.
*   Restrict and closely monitor superuser access within the Sentry application to minimize the attack surface.
*   Implement input validation and sanitization measures to prevent the deserialization of untrusted data, mitigating similar vulnerabilities in the future.
