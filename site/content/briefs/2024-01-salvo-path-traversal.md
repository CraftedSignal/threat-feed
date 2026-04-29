---
title: Salvo Web Framework Path Traversal Vulnerability
slug: 2024-01-salvo-path-traversal
description: Salvo web framework versions 0.39.0 through 0.89.2 are vulnerable to Path Traversal and Access Control Bypass, allowing unauthenticated external attackers to bypass proxy routing constraints and access unintended backend paths.
date: "2026-03-24T00:16:29Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - access-control-bypass
  - web-framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33242
rules:
  - title: Detect Salvo Path Traversal Attempt via URL
    description: Detects attempts to exploit CVE-2026-33242 in Salvo web framework by identifying '../' sequences in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Salvo Path Traversal Attempt via HTTP Request
    description: Detects attempts to exploit CVE-2026-33242 in Salvo web framework by identifying '../' sequences in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Salvo, a Rust web framework, is vulnerable to a path traversal and access control bypass in versions 0.39.0 through 0.89.2. This vulnerability, identified as CVE-2026-33242, resides within the `salvo-proxy` component. The flaw allows unauthenticated, remote attackers to circumvent proxy routing restrictions and gain access to backend resources that should be protected. The root cause is the `encode_url_path` function's failure to properly sanitize "../" sequences within URLs. This leads to the sequences being passed directly to the upstream server without re-encoding, thus bypassing intended access controls. Organizations using affected versions of Salvo are vulnerable until they upgrade to version 0.89.3, which contains the necessary patch.

## Attack Chain

1. An unauthenticated attacker identifies a Salvo web server running a vulnerable version (0.39.0 - 0.89.2).
2. The attacker crafts a malicious HTTP request targeting a proxied endpoint.
3. The crafted request includes a URL containing "../" sequences to traverse directories outside the intended proxy path.
4. The `encode_url_path` function fails to properly normalize or re-encode the "../" sequence.
5. The unsanitized URL is forwarded to the upstream server behind the proxy.
6. The upstream server processes the request, granting access to unintended files or endpoints due to the path traversal.
7. The attacker gains unauthorized access to sensitive information, protected functionalities, or administrative interfaces.
8. The attacker may further exploit the compromised resource to escalate privileges or compromise the entire system.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to bypass intended access controls and access sensitive backend resources. The CVSS v3.1 score is 7.5. This could lead to exposure of confidential data, unauthorized modification of system settings, or complete system compromise, depending on the nature of the accessible resources. The number of affected deployments is currently unknown but depends on the adoption rate of the Salvo framework.

## Recommendation

*   Upgrade Salvo to version 0.89.3 or later to patch CVE-2026-33242.
*   Implement web application firewall (WAF) rules to detect and block requests containing "../" sequences in the URL, mitigating potential path traversal attempts.
*   Deploy the Sigma rules provided below to your SIEM to detect exploitation attempts targeting this vulnerability.
*   Review and harden proxy configurations to ensure proper input validation and sanitization of URLs.
