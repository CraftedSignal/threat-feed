---
title: Path Traversal Vulnerability in ZFile Download Endpoint
slug: 2026-09-zfile-path-traversal
description: ZFile versions through 5.0.5 are vulnerable to a path traversal attack allowing unauthenticated attackers to download arbitrary files via manipulated share link query parameters.
date: "2026-09-14T23:36:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zfile:zfile:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-vulnerability
  - information-disclosure
vendors:
  - ZFile
products:
  - ZFile (<= 5.0.5)
cves:
  - id: CVE-2026-91144
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91144
rules:
  - title: Detects CVE-2026-91144 Exploitation - Path Traversal in ZFile
    description: Detects path traversal attempts in ZFile download queries by monitoring for directory traversal sequences within query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Review exposed ZFile instances and restrict external access until patches are available.
      owner: IT Operations
      due: 24h
      evidence: High severity (7.5) vulnerability in public-facing interface.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ZFile to a version > 5.0.5.
      owner: IT Operations
      addresses: CVE-2026-91144
      evidence: NVD vulnerability mitigation guidance.
---

ZFile, a popular file directory software, contains a critical path traversal vulnerability (CVE-2026-91144) in versions through 5.0.5. The vulnerability resides within the download endpoint, which fails to adequately validate user-supplied file paths against the base directory defined for a specific share link. An attacker who possesses a valid share link can manipulate query parameters to access and retrieve files outside of the intended, restricted directory. This flaw effectively grants unauthorized read access to the underlying server filesystem, potentially leading to the exposure of sensitive configuration files, environment variables, or other private data stored on the host. The issue is exacerbated by the fact that the endpoint does not require authentication, making it accessible to any party with a public share link. Defenders should prioritize updating ZFile to a patched version once available and monitor access logs for anomalous path structures.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass directory restrictions and exfiltrate arbitrary files from the server. This could lead to full system information disclosure, including compromise of credentials or system configuration, depending on the server's permissions.

## Recommendation

* Upgrade all instances of ZFile to a version newer than 5.0.5 immediately upon release of a security patch.
* Deploy the provided Sigma rule to monitor for path traversal attempts targeting the ZFile download endpoint.
* Configure web application firewalls to alert on requests containing sequences such as "../" or "..\\" in query parameters directed at ZFile download handlers.
