---
title: modelscope agentscope Server-Side Request Forgery Vulnerability (CVE-2026-6604)
slug: 2024-01-agentscope-ssrf
description: A server-side request forgery vulnerability (CVE-2026-6604) exists in modelscope agentscope up to version 1.0.18, allowing remote attackers to manipulate the image_url or audio_file_url arguments to perform SSRF attacks via the Cloud Metadata Endpoint component.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-6604
  - modelscope
  - agentscope
vendors:
  - ModelScope
products:
  - agentscope
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6604
rules:
  - title: Detect modelscope agentscope SSRF Attempt via prepare_image
    description: Detects potential SSRF exploitation attempts targeting the prepare_image function in modelscope agentscope.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect modelscope agentscope SSRF Attempt via openai_audio_to_text
    description: Detects potential SSRF exploitation attempts targeting the openai_audio_to_text function in modelscope agentscope.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect modelscope agentscope SSRF Attempt via _parse_url
    description: Detects potential SSRF exploitation attempts targeting the _parse_url function in modelscope agentscope.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-6604, affects modelscope agentscope versions up to 1.0.18. The vulnerability resides within the `_parse_url`, `prepare_image`, and `openai_audio_to_text` functions of the `src/agentscope/tool/_multi_modality/_openai_tools.py` file, specifically impacting the Cloud Metadata Endpoint component. This flaw allows remote attackers to manipulate the `image_url` or `audio_file_url` arguments, potentially enabling them to make arbitrary HTTP requests from the affected server. The exploit is publicly available, increasing the risk of exploitation. The vendor was contacted, but did not respond.

## Attack Chain

1.  Attacker identifies a vulnerable modelscope agentscope instance running version 1.0.18 or earlier.
2.  The attacker crafts a malicious request targeting the `_parse_url`, `prepare_image`, or `openai_audio_to_text` functions within `src/agentscope/tool/_multi_modality/_openai_tools.py`.
3.  The malicious request includes a manipulated `image_url` or `audio_file_url` parameter pointing to an internal or external resource controlled by the attacker.
4.  The agentscope application processes the request and attempts to retrieve the resource specified in the manipulated URL.
5.  Due to the SSRF vulnerability, the server makes an HTTP request to the attacker-controlled resource, potentially bypassing firewalls or other security controls.
6.  The attacker's server receives the request from the vulnerable agentscope instance.
7.  The attacker can then use the agentscope instance as a proxy to access internal resources or perform other malicious actions.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-6604) could allow an attacker to access sensitive information on the internal network, perform unauthorized actions on behalf of the server, or potentially escalate privileges. Depending on the configuration and network topology, the attacker could potentially gain access to other systems and data within the organization's infrastructure. This can lead to data breaches, service disruptions, and other security incidents.

## Recommendation

*   Upgrade modelscope agentscope to a patched version beyond 1.0.18 to remediate CVE-2026-6604.
*   Implement input validation and sanitization on the `image_url` and `audio_file_url` parameters to prevent manipulation (reference the vulnerability description).
*   Monitor web server logs for suspicious requests targeting the `_parse_url`, `prepare_image`, and `openai_audio_to_text` functions in `src/agentscope/tool/_multi_modality/_openai_tools.py` (reference the attack chain).
*   Deploy the Sigma rules provided to detect potential exploitation attempts in your environment.
