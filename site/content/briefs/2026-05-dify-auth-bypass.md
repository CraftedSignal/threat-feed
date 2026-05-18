---
title: Dify Authorization Bypass Vulnerability (CVE-2026-41947)
slug: 2026-05-dify-auth-bypass
description: Dify version 1.14.1 and prior contains an authorization bypass vulnerability (CVE-2026-41947) that allows authenticated editor users to set and enable trace configurations for any application regardless of tenant ownership, potentially leading to information disclosure by redirecting application messages to attacker-controlled LLM trace providers.
date: "2026-05-18T15:17:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - cve-2026-41947
vendors:
  - Dify
products:
  - Dify
  - Dify Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41947
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41947
rules:
  - title: Detect Dify Unauthorized Trace Configuration Change
    description: Detects CVE-2026-41947 exploitation — Modification of a trace configuration by a user lacking tenant ownership, potentially leading to information disclosure.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Dify Trace Configuration Creation to External Host
    description: Detects creation of a Dify trace configuration pointing to an external host.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Dify, a platform for building AI-native applications, is vulnerable to an authorization bypass (CVE-2026-41947) affecting version 1.14.1 and prior. Authenticated users with editor privileges can exploit this vulnerability to manipulate trace configurations across different tenants. The vulnerability stems from a lack of tenant ownership verification when setting and enabling trace configurations. A successful exploit allows an attacker to redirect messages and responses from victim applications to attacker-controlled LLM trace providers, effectively intercepting and potentially exfiltrating sensitive data processed by the targeted applications. The Dify Cloud offering allows unauthenticated free self-registration, lowering the barrier to entry for attackers.

## Attack Chain

1. Attacker registers an account on Dify Cloud (if using Dify Cloud) or gains editor privileges on a Dify instance.
2. Attacker authenticates to the Dify platform using their account credentials.
3. Attacker identifies the target application they wish to monitor by enumerating available applications or through other means.
4. Attacker crafts a malicious API request to set the trace configuration for the target application. The request specifies an attacker-controlled LLM trace provider endpoint.
5. The trace configuration endpoint lacks proper tenant ownership checks, allowing the attacker to modify the configuration of the target application.
6. Attacker enables the trace configuration for the target application.
7. All subsequent messages and responses from the victim application are redirected to the attacker-controlled LLM trace provider.
8. Attacker intercepts and analyzes the redirected messages to extract sensitive information.

## Impact

Successful exploitation of CVE-2026-41947 can lead to unauthorized access to sensitive information processed by Dify applications. An attacker can intercept application messages and responses, potentially exposing confidential data, intellectual property, or personally identifiable information (PII). The severity of the impact depends on the nature of the data handled by the compromised applications, but the vulnerability could affect all Dify users.

## Recommendation

*   Apply the necessary patches or upgrade to a version of Dify beyond 1.14.1 to remediate CVE-2026-41947.
*   Implement the "Detect Dify Unauthorized Trace Configuration Change" Sigma rule to identify potential exploitation attempts.
*   Implement the "Detect Dify Trace Configuration Creation to External Host" Sigma rule to identify creation of traces that lead to external endpoints.
*   Review and restrict editor privileges to only those users who require them, minimizing the attack surface.
