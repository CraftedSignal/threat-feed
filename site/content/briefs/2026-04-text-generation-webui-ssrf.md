---
title: text-generation-webui SSRF Vulnerability (CVE-2026-35486)
slug: 2026-04-text-generation-webui-ssrf
description: The text-generation-webui application before version 4.3 is vulnerable to server-side request forgery (SSRF) due to insufficient validation of user-supplied URLs by the superbooga and superboogav2 RAG extensions, potentially leading to credential theft and internal network reconnaissance.
date: "2026-04-07T16:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - text-generation-webui
  - cve-2026-35486
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35486
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35486
  - https://github.com/oobabooga/text-generation-webui/security/advisories/GHSA-jvrj-w5hq-6cp2
rules:
  - title: Detect text-generation-webui SSRF Attempt
    description: Detects attempts to exploit the text-generation-webui SSRF vulnerability (CVE-2026-35486) by monitoring requests to cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1552.005
    data_sources:
      - webserver
      - linux
  - title: Detect text-generation-webui RAG extensions URL fetch
    description: Detects text-generation-webui RAG extensions fetching URL.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The text-generation-webui application is an open-source web interface for running Large Language Models (LLMs). Prior to version 4.3, the superbooga and superboogav2 RAG (Retrieval-Augmented Generation) extensions are susceptible to a Server-Side Request Forgery (SSRF) vulnerability. These extensions fetch user-provided URLs using the `requests.get()` function without proper validation. Specifically, there are no checks for URL schemes (e.g., `file://`, `gopher://`), IP address filtering, or hostname whitelisting. This lack of validation allows a malicious actor to craft URLs that target internal resources, cloud metadata endpoints (e.g., AWS, Azure, GCP), and other sensitive services. Successful exploitation can lead to the exfiltration of sensitive data, including IAM credentials, and allow an attacker to probe internal network infrastructure. Version 4.3 of text-generation-webui addresses this vulnerability.

## Attack Chain

1. An attacker identifies an instance of text-generation-webui running a vulnerable version (prior to 4.3) with the superbooga or superboogav2 RAG extension enabled.
2. The attacker crafts a malicious URL targeting a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
3. The attacker injects the malicious URL into a text-generation-webui RAG extension user input field.
4. The application, using the `requests.get()` function, fetches the content from the attacker-controlled URL without validation.
5. The cloud metadata, containing potentially sensitive information like temporary IAM credentials, is retrieved by the application.
6. The retrieved data is processed through the RAG pipeline.
7. The attacker leverages the RAG pipeline to extract the content from the application.
8. The attacker uses the exfiltrated credentials to access and compromise other resources within the victim's cloud environment.

## Impact

Successful exploitation of CVE-2026-35486 can have significant consequences. An attacker can potentially gain unauthorized access to cloud resources by stealing IAM credentials. This could lead to data breaches, service disruption, and financial loss. The vulnerability affects any text-generation-webui instance running a version prior to 4.3 with the vulnerable RAG extensions enabled, impacting individuals and organizations utilizing this software for LLM-based applications.

## Recommendation

*   Upgrade text-generation-webui to version 4.3 or later to remediate the SSRF vulnerability (CVE-2026-35486).
*   Deploy the Sigma rule "Detect text-generation-webui SSRF Attempt" to your SIEM to detect exploitation attempts targeting cloud metadata endpoints.
*   Monitor web server logs for outbound connections to internal IP addresses (e.g., 169.254.169.254) originating from the text-generation-webui application.
