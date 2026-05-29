---
title: Manga-Image-Translator Remote Code Execution via Pickle Deserialization (CVE-2026-10042)
slug: 2026-05-manga-image-rce
description: Manga-image-translator is vulnerable to remote code execution (CVE-2026-10042) in the shared API server mode due to unsafe deserialization of untrusted pickle data, allowing a remote attacker to execute arbitrary code in the server process.
date: "2026-05-29T15:17:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - deserialization
  - CVE-2026-10042
  - manga-image-translator
products:
  - manga-image-translator
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Arbitrary Code Execution
cves:
  - id: CVE-2026-10042
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10042
rules:
  - title: Detect CVE-2026-10042 Exploitation Attempt via Pickle Deserialization
    description: Detects CVE-2026-10042 exploitation attempt via HTTP POST requests to /execute or /simple_execute endpoints with potentially malicious pickle data in the request body.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1202
    data_sources:
      - webserver
  - title: Detect manga-image-translator Default Docker Deployment as Root
    description: Detects manga-image-translator running in a Docker container as the root user, which exacerbates the CVE-2026-10042 vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Manga-image-translator is susceptible to a critical remote code execution vulnerability, identified as CVE-2026-10042, affecting the shared API server mode. The root cause lies in the unsafe deserialization of untrusted pickle data within the `share.py` module. Specifically, the `/execute/{method_name}` and `/simple_execute/{method_name}` endpoints are vulnerable, as they deserialize attacker-controlled HTTP request bodies using the `pickle.loads()` function. This flaw allows a remote attacker to supply a specially crafted pickle payload, leading to the execution of arbitrary code within the server process. The default Docker deployment runs as root, which exacerbates the issue, potentially resulting in full container compromise. Defenders should prioritize detection and mitigation of this vulnerability.

## Attack Chain

1.  Attacker identifies a manga-image-translator instance running in shared API server mode.
2.  Attacker crafts a malicious pickle payload designed to execute arbitrary code on the server.
3.  Attacker sends an HTTP POST request to either the `/execute/{method_name}` or `/simple_execute/{method_name}` endpoint.
4.  The HTTP request body contains the crafted pickle payload.
5.  The `share.py` module's vulnerable endpoint calls `pickle.loads()` on the attacker-controlled payload.
6.  `pickle.loads()` deserializes the malicious payload, triggering arbitrary code execution.
7.  The attacker gains code execution within the container, running as root.
8.  The attacker leverages the compromised container to perform further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful exploitation of CVE-2026-10042 allows a remote attacker to achieve remote code execution on the affected manga-image-translator server. When running in the default Docker deployment as root, this leads to full container compromise. The CVSS v3.1 base score for this vulnerability is 9.8, indicating a critical severity. The lack of information about affected deployments makes it hard to determine the number of victims, but exploitation could lead to data breaches, service disruption, or further attacks originating from the compromised server.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-10042 Exploitation Attempt via Pickle Deserialization" to your SIEM to detect potential exploitation attempts based on suspicious HTTP POST requests to the vulnerable endpoints.
*   Enable webserver logging to monitor HTTP requests and responses to activate the Sigma rule effectively.
*   Apply appropriate input validation and sanitization techniques to prevent the deserialization of untrusted data.
*   Consider running the manga-image-translator container with a non-root user to reduce the impact of a successful container compromise.
