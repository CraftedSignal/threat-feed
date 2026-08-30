---
title: SSRF Vulnerability in SiYuan via DNS Rebinding
slug: 2026-08-siyuan-ssrf
description: SiYuan versions prior to 3.8.1 are vulnerable to server-side request forgery through a DNS rebinding attack, enabling unauthorized access to cloud metadata services and internal network resources.
date: "2026-08-28T15:13:11Z"
lastmod: "2026-08-30T17:11:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan:siyuan:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - cloud-security
  - web-vulnerability
  - xss
  - SiYuan
vendors:
  - SiYuan
products:
  - SiYuan (< 3.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The source references the use of malicious domains for SSRF exploitation, which is often facilitated via phishing or deceptive links.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can submit malicious bazaar packages with HTML/script payloads in the name field that execute in users' browsers when uninstalling packages or unlocking encrypted notebooks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Attackers can submit malicious bazaar packages with HTML/script payloads in the name field that execute in users' browsers.
    confidence_band: high
cves:
  - id: CVE-2026-82234
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82234
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82653
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82654
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SiYuan to 3.8.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies version 3.8.1 as the fix for CVE-2026-82234.
  mitigation_plan:
    - priority: immediate
      action: Block egress traffic to 169.254.169.254 from SiYuan hosts
      owner: IT Operations
      addresses: CVE-2026-82234
      evidence: Source confirms cloud metadata service access is a primary target of the SSRF.
updates:
  - at: "2026-08-30T17:11:45Z"
    level: L2
    summary: added coverage for SiYuan (< 3.8.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82653
  - at: "2026-08-30T17:11:51Z"
    level: L2
    summary: added coverage for SiYuan (< 3.8.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82654
---

SiYuan versions before 3.8.1 are susceptible to a critical server-side request forgery (SSRF) vulnerability identified as CVE-2026-82234. The flaw exists within the 'http_request' and 'web_fetch' agent tools, which perform DNS resolution checks only at the time of the request guard. Because the application fails to validate the IP address resolved during the subsequent connection phase, it becomes vulnerable to DNS rebinding attacks. An attacker can supply a domain that resolves to a benign public IP address during the initial guard check and then switches to a private, restricted, or cloud metadata IP address (e.g., 169.254.169.254) during the actual connection. This allows remote attackers to bypass security filters and interact with internal network services or exfiltrate sensitive environment metadata that would otherwise be protected from external access. This vulnerability poses a significant risk to cloud-hosted deployments of SiYuan.

## Attack Chain

1. The attacker registers a malicious domain under their control, configured with a low time-to-live (TTL) value.
2. The attacker triggers a request via the SiYuan 'http_request' or 'web_fetch' tool, pointing it at the malicious domain.
3. The SiYuan application performs the initial DNS resolution guard check and receives the benign public IP address.
4. The guard check passes as the IP address is deemed safe by the application logic.
5. The attacker updates the DNS record for the domain to point to an internal resource (e.g., cloud metadata service or internal API).
6. The SiYuan application proceeds to the connection phase and performs a second resolution (or uses the cached connection) against the new, attacker-controlled internal IP.
7. The application fetches data from the internal resource, inadvertently exfiltrating the response content back to the attacker.

## Impact

Successful exploitation allows an unauthenticated attacker to interact with internal services that are not exposed to the internet. In cloud environments, this can lead to the exfiltration of instance metadata, including sensitive cloud credentials, environment variables, and configuration details. This can further enable lateral movement or complete compromise of the cloud instance depending on the information exposed by the metadata service.

## Recommendation

* Upgrade all SiYuan installations to version 3.8.1 or later to implement proper connect-time IP validation.
* Implement strict egress filtering on the host machine to block access to the cloud metadata service (e.g., 169.254.169.254) and internal private IP ranges (RFC1918) unless explicitly required.
* Deploy network-level monitoring to identify anomalous DNS queries directed toward services that typically perform internal fetch operations.
