---
title: Server-Side Request Forgery in Unstructured URL Partitioning
slug: 2026-09-unstructured-ssrf
description: The Unstructured library is vulnerable to unauthenticated full-read Server-Side Request Forgery (SSRF) via the partition(), partition_html(), and partition_md() functions, allowing attackers to access internal network services and cloud metadata endpoints.
date: "2026-09-03T18:03:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:unstructured:unstructured:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - library-vulnerability
  - python
products:
  - unstructured (>= 0.4.7, < 0.24.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The unstructured library is vulnerable to Server-Side Request Forgery (SSRF) due to a lack of host validation when fetching URLs.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: The attacker can use error messages and connection timing to perform network reconnaissance.
    confidence_band: high
cves:
  - id: CVE-2026-71428
    cvss: 9.3
    epss: 0.0025
references:
  - https://github.com/advisories/GHSA-4mvj-m6j5-pmf7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71428
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade unstructured to version 0.24.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-71428 remediation
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on ingestion servers to deny access to 169.254.169.254 and RFC1918 address space
      owner: Network Security
      addresses: CVE-2026-71428
      evidence: Mitigates SSRF impact even if library is unpatched
---

The `unstructured` Python library, widely used for URL ingestion in agent frameworks such as LangChain and LlamaIndex, contains a critical Server-Side Request Forgery (SSRF) vulnerability. The flaw exists in the `partition()`, `partition_html()`, and `partition_md()` functions, which utilize `requests.get()` to fetch remote content without performing host validation, URL filtering, or restricting requests to private/loopback IP spaces. 

This vulnerability allows an attacker to provide an arbitrary URL to these functions, which the application then requests. Because the library returns the response body as text, it facilitates a full-read SSRF. This enables attackers to reach sensitive internal services, such as administrative APIs, databases, and microservices, or to query cloud instance metadata services (IMDS). The vulnerability has existed since version 0.4.7 (February 2023) and remains present in versions up to 0.24.0. The lack of timeouts in `partition_md()` further introduces potential denial-of-service risks via slow-loris patterns.

## Attack Chain

1. Attacker identifies an internet-facing application that uses the `unstructured` library to process user-provided URLs (e.g., an LLM agent feature or link-preview generator).
2. Attacker crafts a malicious URL pointing to an internal resource (e.g., `http://127.0.0.1:80` or `http://169.254.169.254/latest/meta-data/`).
3. Attacker submits the crafted URL to the target application's ingestion endpoint.
4. The application passes the URL to `unstructured.partition.auto.partition()`.
5. The library performs an unvalidated HTTP GET request to the target internal host using the server's identity.
6. The target internal service processes the request and returns sensitive data (e.g., IMDS credentials or admin dashboard HTML) to the library.
7. The library parses the returned sensitive data as document text and embeds it into the LLM context or application output.
8. Attacker views the output containing the exfiltrated sensitive data.

## Impact

Successful exploitation allows attackers to perform reconnaissance on internal networks, gain access to sensitive internal HTTP services (e.g., Redis, Consul, Kubernetes API), and exfiltrate cloud instance credentials from metadata endpoints that permit unauthenticated GET requests. Organizations leveraging this library within agentic frameworks are at significant risk of unauthorized internal access, as the vulnerability resides within the ingestion layer, making every downstream implementation potentially susceptible.

## Recommendation

1. Upgrade the `unstructured` library to version 0.24.0 or later immediately to patch CVE-2026-71428.
2. If an immediate upgrade is not possible, implement strict URL validation logic at the application layer to block requests to private IP ranges (e.g., `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) and the cloud metadata link-local address (`169.254.169.254`).
3. Restrict egress traffic from servers running document ingestion workflows using host-based firewalls or network egress filtering to prevent unauthorized internal connectivity.
