---
title: Server-Side Request Forgery in mcp-webresearch (CVE-2026-65056)
slug: 2026-07-mcp-webresearch-ssrf
description: A server-side request forgery (SSRF) vulnerability in mcp-webresearch version 0.1.7 allows attackers to bypass URL protocol validation by supplying private IP addresses, enabling them to leverage prompt injection to steer an LLM-controlled URL, forcing the server's Playwright browser to access internal network services and cloud instance metadata, which leads to the exfiltration of sensitive internal content, including credentials, into the model's context.
date: "2026-07-21T21:23:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - cloud
  - data-exfiltration
  - cve-2026-65056
  - llm-security
products:
  - mcp-webresearch 0.1.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: mcp-webresearch 0.1.7 contains a server-side request forgery vulnerability that allows attackers to access internal network services by supplying loopback, link-local, or cloud metadata addresses to the visit_page tool, which only validates the URL protocol without filtering private or reserved IP ranges.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Instance Metadata API
    evidence: Attackers can steer the LLM-controlled URL argument through prompt injection to navigate the server's Playwright browser to internal endpoints such as cloud instance metadata services
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: causing the server to return sensitive internal page content including credentials into the model context.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over Web Service
    evidence: causing the server to return sensitive internal page content including credentials into the model context.
    confidence_band: high
cves:
  - id: CVE-2026-65056
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65056
---

A critical server-side request forgery (SSRF) vulnerability, identified as CVE-2026-65056, has been discovered in version 0.1.7 of the mcp-webresearch application. This flaw enables attackers to bypass URL protocol validation within the `visit_page` tool by exploiting a lack of filtering for private or reserved IP ranges. The core issue lies in the tool's inability to prevent connections to internal network services, including loopback, link-local, and cloud metadata addresses, once the URL argument is controlled. Through prompt injection, adversaries can manipulate the application's underlying Large Language Model (LLM) to direct the server's Playwright browser to sensitive internal endpoints. This malicious navigation allows the attacker to retrieve and exfiltrate internal page content, such as system configurations and credentials, by embedding this information directly into the LLM's context. The vulnerability poses a significant risk of unauthorized data access and potential lateral movement within a compromised environment, impacting any organization deploying `mcp-webresearch` version 0.1.7.

## Attack Chain

1. An attacker identifies a deployed instance of the `mcp-webresearch 0.1.7` application.
2. The attacker crafts a prompt injection payload designed to manipulate the Large Language Model's (LLM) URL argument.
3. The prompt injection payload includes a Uniform Resource Locator (URL) pointing to an internal network address, such as `http://169.254.169.254/latest/meta-data/` for cloud metadata services, or a private IP range.
4. The `visit_page` tool within `mcp-webresearch` processes the crafted URL, performing only protocol validation and failing to filter out private or reserved IP ranges.
5. The `visit_page` tool directs the server's embedded Playwright browser to access the attacker-specified internal endpoint.
6. The Playwright browser accesses the internal service (e.g., cloud metadata API), retrieving sensitive content like instance credentials, authentication tokens, or other internal application data.
7. The sensitive content obtained from the internal service is returned and embedded into the LLM's model context.
8. The attacker then extracts the sensitive information (e.g., credentials) from the LLM's output, achieving data exfiltration.

## Impact

This vulnerability allows attackers to gain unauthorized access to sensitive internal network services and cloud metadata APIs, including services running on loopback and link-local addresses. Successful exploitation leads to the exfiltration of critical data, such as system configurations, authentication tokens, and credentials, directly into the attacker-controlled LLM context. While specific victim counts are not available, any organization utilizing `mcp-webresearch` version 0.1.7 is at risk. The direct consequence of a successful attack is a significant data breach, potentially enabling further lateral movement and persistent access within the targeted infrastructure.

## Recommendation

* Patch CVE-2026-65056 by updating mcp-webresearch to a version where this SSRF vulnerability is remediated immediately.
* Implement network egress filtering on servers running `mcp-webresearch` to block outbound connections to private IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and cloud metadata IPs like 169.254.169.254) from the `mcp-webresearch` service.
* Monitor `mcp-webresearch` application logs for any unusual URL requests to internal or reserved IP addresses within the `visit_page` functionality.
* Monitor network connection logs for outbound connections originating from the `mcp-webresearch` process to cloud instance metadata APIs or other internal network services.
