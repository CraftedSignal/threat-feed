---
title: Datamodel Code Generator Vulnerable to SSRF via URL Parameter
slug: 2026-07-datamodel-code-generator-ssrf
description: The `datamodel-code-generator` tool, specifically versions from `0.9.1` up to `0.60.2`, is vulnerable to Server-Side Request Forgery (SSRF) when using the `--url` argument with the `[http]` extra installed, allowing attackers to access internal network resources and exfiltrate sensitive data into generated Python files.
date: "2026-07-28T21:34:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - supply-chain
  - code-generation
  - python
  - vulnerability
vendors:
  - koxudaxi
products:
  - datamodel-code-generator (0.9.1 - 0.60.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Internal port scan / disclosure. Iterating `--url http://127.0.0.1:<port>/health` probes localhost services; non-HTML, non-error responses confirm a service and leak its body into the generated file.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: ""
    evidence: A blog post or README example reads `datamodel-codegen --url https://schemas.example.com/user.json -o user.py`. The attacker controls `example.com`, redirects to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`, and the IAM credentials end up as a docstring in `user.py`.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1538
    technique_name: Cloud Infrastructure Discovery
    evidence: IAM credentials end up as a docstring in `user.py`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rfr2-mq9m-x2qx
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
  - type: url
    value: http://127.0.0.1:<port>/health
ioc_counts:
  ip: 1
  url: 2
rules:
  - title: Detect datamodel-code-generator SSRF attempts to internal IPs
    description: Detects CVE-2026-54691 exploitation attempts where datamodel-code-generator's --url parameter targets internal, private, or cloud metadata IP addresses, indicating an SSRF attempt or success.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - impact
    techniques:
      - T1046
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Versions `0.9.1` through `0.60.2` of the `datamodel-code-generator` tool are susceptible to Server-Side Request Forgery (SSRF) when the optional `[http]` extra is installed. This vulnerability arises because the tool's built-in HTTP fetcher, utilized when the `--url` command-line argument is supplied, lacks critical validation for host and IP addresses and unconditionally follows HTTP redirects. An attacker can craft a malicious URL that redirects to internal network resources, loopback addresses, private IP ranges, or cloud metadata services like `169.254.169.254`. If successfully exploited, the tool will fetch content from these internal destinations and embed any sensitive information (e.g., IAM credentials, internal API responses) directly into the generated `.py` source code. This poses a significant risk of internal network reconnaissance, sensitive data disclosure, and credential exfiltration, particularly if the generated files are committed to a public or attacker-accessible repository. Organizations using `datamodel-code-generator` should upgrade to version `0.61.0` or later to mitigate this risk.

## Attack Chain

1. An attacker crafts a malicious external URL (e.g., `https://attacker.com/schema.json`) that issues an HTTP 302 redirect to an internal network resource, a private IP address, or a cloud metadata service (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`).
2. A victim executes the `datamodel-code-generator` tool, providing the attacker-controlled external URL via the `--url` command-line argument.
3. The `datamodel-code-generator` tool, specifically its `http.get_body` function, initiates an HTTP GET request to the provided external URL.
4. The external server responds with an HTTP 302 redirect to the internal target specified by the attacker.
5. Due to the `follow_redirects=True` setting and absence of host/IP validation, `datamodel-code-generator` transparently follows the redirect and fetches content from the sensitive internal resource, effectively bypassing network boundaries.
6. The response body from the internal resource (e.g., IAM role credentials, confidential internal API responses, or system information) is processed and interpreted as a schema.
7. Sensitive information extracted from this internal response body is subsequently embedded into the generated Python `.py` source file, for example, as docstrings, class attributes, or field descriptions.
8. The generated `.py` file, now containing the exfiltrated sensitive data, is potentially committed to a version control system, making the internal information accessible to the attacker or a wider audience.

## Impact

This SSRF vulnerability can have significant consequences, primarily affecting organizations that use `datamodel-code-generator` with unverified URLs or within environments where internal services are accessible from development workstations or CI/CD pipelines. The observed damages include internal network reconnaissance through port scanning localhost or private IP ranges, and the disclosure of highly sensitive information. This can involve the exfiltration of cloud IAM credentials from metadata services (e.g., AWS EC2), internal API keys, or proprietary data from intranet applications. If the generated Python files containing this sensitive data are then committed to a repository, it constitutes a direct exfiltration channel, potentially granting attackers access to cloud infrastructure or other critical internal systems.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.61.0` or higher immediately to patch CVE-2026-54691.
* Deploy the `Detect datamodel-code-generator SSRF attempts to internal IPs` Sigma rule to your SIEM to identify suspicious invocations of the tool targeting internal or private IP addresses.
* Review existing codebases for `datamodel-codegen` invocations that use the `--url` parameter, especially in automated CI/CD pipelines, to ensure URLs are trusted and do not point to attacker-controlled domains or could redirect to internal resources.
* Implement source code analysis tools to scan generated `.py` files for embedded sensitive information (e.g., API keys, credentials, private IPs) that may have resulted from past exploitation of this vulnerability.
