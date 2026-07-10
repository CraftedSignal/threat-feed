---
title: 'CVE-2026-15330: zhayujie CowAgent Server-Side Request Forgery'
slug: 2026-07-cowagent-ssrf
description: A critical server-side request forgery (SSRF) vulnerability, CVE-2026-15330, exists in zhayujie CowAgent up to version 2.1.1, allowing remote attackers to manipulate the 'image' argument in the Vision Tool component's `_build_image_content` or `_download_to_data_url` functions to access internal resources or conduct port scanning.
date: "2026-07-10T05:24:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - ssrf
  - remote-code-execution
  - network
vendors:
  - zhayujie
products:
  - CowAgent
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument image can lead to server-side request forgery. The attack can be launched remotely. The exploit has been publicly disclosed and may be utilized.
    confidence_band: high
cves:
  - id: CVE-2026-15330
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15330
rules:
  - title: Detect CVE-2026-15330 Exploitation - CowAgent SSRF via 'image' argument
    description: Detects exploitation of CVE-2026-15330, an SSRF vulnerability in zhayujie CowAgent, by looking for requests to endpoints potentially invoking the Vision Tool with common SSRF payloads in the 'image' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-15330, has been discovered in zhayujie CowAgent versions up to and including 2.1.1. This flaw specifically impacts the `_build_image_content` and `_download_to_data_url` functions located in the `agent/tools/vision/vision.py` file, part of the Vision Tool component. Attackers can remotely exploit this by crafting a malicious 'image' argument in a request, compelling the CowAgent server to make arbitrary requests to internal or external resources. The vulnerability has been publicly disclosed, increasing the risk of exploitation. Defenders should prioritize upgrading to version 2.1.2 or applying patch e85290cddcbb5ffc9c235927f4c92e5b4c3ec264 immediately to prevent potential network compromise and data exfiltration.

## Attack Chain

1. An attacker crafts a specially designed HTTP request targeting a web endpoint of the zhayujie CowAgent application.
2. The request includes a manipulated `image` argument, pointing to an internal IP address or an otherwise restricted URL (e.g., `http://localhost`, `file:///etc/passwd`, `http://169.254.169.254`).
3. The vulnerable application endpoint processes the incoming request, invoking the `_build_image_content` or `_download_to_data_url` function within `agent/tools/vision/vision.py`.
4. The application, unaware of the malicious intent, attempts to fetch content from the URL specified in the `image` argument.
5. Due to the SSRF vulnerability, the CowAgent server initiates an outbound connection to the attacker-controlled or internal destination URL.
6. This allows the attacker to read arbitrary files from the server, scan internal networks, interact with internal services, or potentially exfiltrate sensitive data.
7. Depending on the success of the internal access, the attacker may pivot to other internal systems or collect credentials for further compromise.

## Impact

Successful exploitation of CVE-2026-15330 can lead to severe consequences for affected organizations. Attackers can leverage the server-side request forgery to access and exfiltrate sensitive data from internal systems that are not directly exposed to the internet. This includes reading local files (e.g., configuration files, credentials), performing port scans of the internal network, and interacting with or exploiting other internal services (e.g., cloud metadata services, internal APIs, databases). The publicly disclosed nature of the exploit increases the likelihood of rapid adoption by malicious actors, potentially leading to widespread compromise for unpatched instances of zhayujie CowAgent.

## Recommendation

* Prioritize upgrading all zhayujie CowAgent instances to version 2.1.2 or later immediately to address CVE-2026-15330.
* Deploy the provided Sigma rule to your SIEM to detect attempts to exploit CVE-2026-15330 via the `image` argument. Tune rule sensitivity to reduce false positives.
* Review web server logs for suspicious requests containing common SSRF payloads in URI parameters, as indicated by the Sigma rule, and investigate any matches.
