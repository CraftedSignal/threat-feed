---
title: Drupal OpenAI Provider Module Vulnerable to Server-Side Request Forgery and Local File Read (CVE-2026-13233)
slug: 2026-07-drupal-openai-ssrf
description: A moderately critical Server-Side Request Forgery (SSRF) vulnerability, CVE-2026-13233, in the Drupal OpenAI Provider (`ai_provider_openai`) module allows attackers to achieve local file reads or access internal network services by manipulating the upstream AI API response, with a public exploit now available.
date: "2026-07-21T10:02:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - SSRF
  - file-read
  - Drupal
  - CVE
  - web-application
vendors:
  - Drupal
products:
  - OpenAI Provider (< 1.1.1)
  - OpenAI Provider (< 1.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public exploit or PoC has been published on Sploitus for CVE-2026-13233... The availability of a working exploit significantly elevates the risk for unpatched systems.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The SSRF included a `file://` local file read... `settings.php` verified by sha256 byte-match, content never emitted → proves 'DB creds in scope' without disclosing them.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: An internal HTTP service with no public port → proves internal SSRF response retrieval with a synthetic token.
    confidence_band: high
cves:
  - id: CVE-2026-13233
    cvss: 3.3
    epss: 0.00161
references:
  - https://sploitus.com/exploit?id=436E852F-DAC6-5315-9EF9-44B559F5FF21
  - https://www.drupal.org/sa-contrib-2026-053
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=436E852F-DAC6-5315-9EF9-44B559F5FF21
  - type: url
    value: https://www.drupal.org/sa-contrib-2026-053
  - type: ip
    value: 169.254.169.254
  - type: path
    value: /etc/hostname
  - type: path
    value: settings.php
ioc_counts:
  ip: 1
  path: 2
  url: 2
rules:
  - title: Detect Potential Drupal OpenAI Provider SSRF to IMDS or RFC1918
    description: Detects CVE-2026-13233 exploitation - anomalous outbound network connections from web server processes to cloud instance metadata service (IMDS) IPs (169.254.169.254) or RFC1918 private IP ranges, indicative of SSRF.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1049
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Drupal OpenAI Provider Local File Read of Sensitive Files
    description: Detects CVE-2026-13233 exploitation - web server processes attempting to read sensitive system files (e.g., /etc/passwd, settings.php) on Linux, indicative of local file read via SSRF.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A public exploit has been released on Sploitus for CVE-2026-13233, a moderately critical Server-Side Request Forgery (SSRF) vulnerability affecting the Drupal OpenAI Provider (`ai_provider_openai`) module. This flaw arises from insufficient input validation, where the module fetches URLs contained in the upstream API response without proper scheme allowlisting. An attacker can compromise or configure a malicious upstream AI API proxy/gateway to respond with crafted URLs, including `file://` schemes or internal network addresses. This allows for sensitive local file reads, such as `/etc/hostname` or `settings.php` (potentially exposing database credentials), and can facilitate access to internal network services like cloud instance metadata endpoints (e.g., `169.254.169.254`). While the publicly released reproducer is "safe" and sandbox-only, the availability of detailed technical information and a confirmed defect mechanism significantly elevates the risk for unpatched Drupal deployments, which remain vulnerable in the wild. The vulnerability was reported privately and fixed in versions 1.1.1 and 1.2.2.

## Attack Chain

1. An attacker compromises or controls an AI API proxy/gateway configured as the upstream for a vulnerable Drupal OpenAI Provider module.
2. The attacker initiates an image generation or similar request via the Drupal module, which triggers a call to the configured upstream AI API.
3. The vulnerable Drupal OpenAI Provider module sends a request to the attacker-controlled upstream AI API.
4. The attacker-controlled upstream API responds with a specially crafted URL (e.g., `file:///path/to/sensitive/file` or `http://internal-ip/service`) embedded within its response.
5. The Drupal OpenAI Provider module, lacking proper scheme allowlisting, attempts to fetch content from the crafted URL provided in the upstream response.
6. The Drupal server performs a local file read (e.g., `/etc/hostname`, `settings.php`, `/etc/passwd`) or an internal network request (SSRF) using the module's privileges.
7. The content of the sensitive file or the response from the internal service is retrieved by the Drupal module.
8. The attacker then extracts the sensitive information (e.g., database credentials, internal network configuration) from the Drupal module's processing output or logs.

## Impact

Successful exploitation of CVE-2026-13233 leads to significant information disclosure. Attackers can read arbitrary local files on the Drupal server, including critical configuration files like `settings.php`, which often contain database credentials, API keys, and other sensitive information. Furthermore, the SSRF capability allows access to internal network resources, potentially exposing cloud instance metadata (e.g., AWS IMDS `169.254.169.254`), internal services, or other systems not directly exposed to the internet. This could enable further lateral movement or privilege escalation within the compromised environment. The vulnerability is rated "moderately critical" by Drupal, indicating a significant risk to confidentiality.

## Recommendation

* Immediately update the Drupal OpenAI Provider module to version 1.1.1 or 1.2.2 to patch CVE-2026-13233.
* Deploy the `Detect Potential Drupal OpenAI Provider SSRF to IMDS or RFC1918` Sigma rule to your SIEM to identify anomalous outbound network connections from web server processes to internal IP ranges.
* Deploy the `Detect Drupal OpenAI Provider Local File Read of Sensitive Files` Sigma rule to your SIEM to detect web server processes attempting to read sensitive system or configuration files like `settings.php` or `/etc/hostname`.
* Enable comprehensive host auditing (e.g., auditd on Linux, EDR) to monitor and log sensitive file access attempts by web processes.
* Ensure proxy and EDR solutions are configured to log and alert on egress to `169.254.169.254` and RFC1918 ranges, especially when originating from web server processes.
* Implement enhanced application audit logging for AI integrations to record `{request_id, actor, target_url, scheme, resolved_ip, content_type}` for all fetch operations.
