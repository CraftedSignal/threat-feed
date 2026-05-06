---
title: OpenClaw Insufficient Access Control in Gateway Agent Session Reset (CVE-2026-35660)
slug: 2026-04-openclaw-reset-vuln
description: OpenClaw before 2026.3.23 contains an insufficient access control vulnerability in the Gateway agent /reset endpoint that allows callers with operator.write permission to reset admin sessions by invoking /reset or /new messages with an explicit sessionKey, bypassing operator.admin requirements.
date: "2026-04-10T17:50:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-35660
  - openclaw
  - access-control
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-35660
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35660
  - https://github.com/openclaw/openclaw/commit/50f6a2f136fed85b58548a38f7a3dbb98d2cd1a0
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wq58-2pvg-5h4f
  - https://www.vulncheck.com/advisories/openclaw-insufficient-access-control-in-gateway-agent-session-reset
rules:
  - title: Detect OpenClaw Session Reset Attempt
    description: Detects attempts to reset admin sessions in OpenClaw via the /reset endpoint, exploiting CVE-2026-35660.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw New Session with Admin Key
    description: Detects attempts to create a new session using an existing admin sessionKey, potentially bypassing authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a yet-to-be-defined application, suffers from an insufficient access control vulnerability (CVE-2026-35660) affecting versions prior to 2026.3.23. The vulnerability exists within the Gateway agent's `/reset` endpoint.  An attacker possessing `operator.write` permissions can exploit this flaw to reset administrative sessions, circumventing the intended `operator.admin` requirement.  Specifically, the vulnerability allows attackers to invoke `/reset` or `/new` messages including an explicit `sessionKey` to manipulate arbitrary sessions. This could lead to unauthorized access and modification of sensitive system configurations, depending on the scope of the OpenClaw application. The vulnerability was disclosed on April 10, 2026.

## Attack Chain

1. An attacker gains unauthorized `operator.write` privileges within the OpenClaw application, potentially through account compromise or privilege escalation from another vulnerability.
2. The attacker crafts a malicious HTTP request targeting the Gateway agent's `/reset` endpoint.
3. The crafted request includes a specific `sessionKey` belonging to an administrative user.
4. Alternatively, the attacker could send a `/new` message containing the admin's `sessionKey`.
5. Due to the insufficient access control, the Gateway agent processes the request, incorrectly resetting the targeted admin session.
6. The administrative user is forcibly logged out of their session, disrupting their work.
7. The attacker could potentially hijack the reset session depending on implementation details.
8. The attacker could then use their elevated access to perform unauthorized actions, such as modifying critical system configurations or accessing sensitive data.

## Impact

Successful exploitation of CVE-2026-35660 allows attackers with `operator.write` privileges to reset arbitrary admin sessions in OpenClaw. This can lead to denial of service for legitimate administrators, and potentially allow the attacker to hijack the reset session or perform unauthorized actions, leading to data breaches or system compromise, depending on the application's functionalities and the scope of admin privileges. The severity is rated as high with a CVSS score of 8.1.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.23 or later to patch CVE-2026-35660.
*   Review and enforce strict access control policies for the OpenClaw application, ensuring that `operator.write` privileges are only granted to trusted users.
*   Monitor web server logs for suspicious requests to the `/reset` endpoint, especially those containing explicit `sessionKey` parameters and correlate with user roles.
*   Deploy the Sigma rule "Detect OpenClaw Session Reset Attempt" to detect exploitation attempts (see below).
