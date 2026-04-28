---
title: PraisonAI SSRF Vulnerability (CVE-2026-34954)
slug: 2026-04-praisonai-ssrf
description: PraisonAI before version 1.5.95 is vulnerable to server-side request forgery (SSRF) due to improper URL validation in the FileTools.download_file() function, potentially allowing attackers to access internal resources.
date: "2026-04-04T14:30:00Z"
severities:
  - high
tags:
  - SSRF
  - CVE-2026-34954
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34954
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34954
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-44c2-3rw4-5gvh
rules:
  - title: PraisonAI Suspicious Outbound Connection
    description: Detects suspicious outbound connections originating from PraisonAI server, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: PraisonAI SSRF - HTTP Request to Internal IP
    description: Detects HTTP requests from PraisonAI to internal IP ranges, indicative of SSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a server-side request forgery (SSRF) vulnerability (CVE-2026-34954) in versions prior to 1.5.95. The vulnerability resides within the `FileTools.download_file()` function of the `praisonaiagents` component. The function validates the destination path of downloaded files but fails to properly sanitize or validate the URL parameter. This allows a malicious actor to supply a crafted URL. The httpx.stream() function, configured with `follow_redirects=True`, will then attempt to resolve and connect to the attacker-controlled URL. Successful exploitation grants the attacker the ability to access internal network services, including cloud metadata endpoints, from the vulnerable PraisonAI server. The vulnerability has been addressed in version 1.5.95.

## Attack Chain

1. An attacker identifies a PraisonAI instance running a version prior to 1.5.95.
2. The attacker crafts a malicious URL targeting an internal service, such as a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/`).
3. The attacker provides the malicious URL to the `FileTools.download_file()` function. This may be achieved through manipulating user input if the application allows users to specify URLs for file downloads.
4. PraisonAI's `FileTools.download_file()` function validates the destination path, but does not validate the attacker supplied URL, which is passed to `httpx.stream()`.
5. The `httpx.stream()` function, following redirects, attempts to connect to the attacker-specified URL.
6. The PraisonAI server initiates an HTTP request to the internal resource.
7. The internal service responds to the PraisonAI server, potentially disclosing sensitive information like cloud credentials or internal configurations.
8. The attacker retrieves the information from the PraisonAI server via the application’s response or logs (depending on how the application handles the response from the internal server).

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to read sensitive information from internal systems or cloud metadata services that would otherwise be inaccessible. The attacker could obtain cloud credentials, configuration files, or other sensitive data, leading to privilege escalation or data breaches. Given the CVSS score of 8.6, this vulnerability poses a significant risk to organizations using vulnerable versions of PraisonAI. The number of affected organizations is currently unknown.

## Recommendation

*   Upgrade PraisonAI to version 1.5.95 or later to patch CVE-2026-34954.
*   Implement network segmentation to limit the PraisonAI server's access to internal resources.
*   Deploy the Sigma rule "PraisonAI Suspicious Outbound Connection" to detect potential SSRF attempts.
*   Monitor web server logs for unusual outbound connections originating from the PraisonAI server.
