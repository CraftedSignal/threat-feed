---
title: Stored XSS in OpenClaw Dashboard via Audit Logs (CVE-2026-66418)
slug: 2026-07-openclaw-xss
description: OpenClaw Dashboard v3.0.0 is vulnerable to stored XSS via failed login attempts, allowing unauthenticated attackers to execute arbitrary scripts in an administrator's session.
date: "2026-07-30T21:31:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-security
  - xss
  - cve-2026-66418
vendors:
  - OpenClaw
products:
  - OpenClaw Dashboard (3.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenClaw Dashboard v3.0.0 contains a stored cross-site scripting vulnerability that allows unauthenticated remote attackers to inject arbitrary HTML and script payloads by submitting a crafted username in a failed login POST request.
    confidence_band: high
cves:
  - id: CVE-2026-66418
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66418
---

OpenClaw Dashboard version 3.0.0 contains a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-66418. The flaw exists within the application's audit logging mechanism, which records the username provided during failed login attempts without proper sanitization or encoding. Because the application renders these log entries in an administrator's notification panel using the innerHTML property, an attacker can inject malicious JavaScript payloads directly into the username field of a POST request. The vulnerability is compounded by a permissive Content-Security-Policy (CSP) that allows inline event handlers, enabling the injected script to execute within the context of an authenticated administrator session. A successful exploit grants the attacker the ability to perform actions on behalf of the administrator, including editing agent instructions or altering system configuration settings.

## Impact

The vulnerability allows unauthenticated remote attackers to achieve full administrative control over the OpenClaw Dashboard instance. Successful exploitation can lead to unauthorized modification of critical system configurations and agent instructions, potentially resulting in full compromise of the managed infrastructure or exfiltration of sensitive telemetry data processed by the OpenClaw platform.

## Recommendation

- Upgrade OpenClaw Dashboard to a patched version once released by the vendor.
- Implement a restrictive Content-Security-Policy (CSP) that disallows 'unsafe-inline' and prevents the use of inline event handlers to mitigate the impact of stored XSS.
- Apply strict input validation and output encoding on all fields, particularly those recorded in audit logs and rendered in administrative interfaces.
- Review web access logs for anomalous login attempts containing unusual characters, script tags, or non-standard username formatting.
