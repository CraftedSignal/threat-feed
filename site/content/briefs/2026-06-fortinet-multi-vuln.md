---
title: Multiple Critical Vulnerabilities in Fortinet Products Lead to RCE and Data Exposure
slug: 2026-06-fortinet-multi-vuln
description: Multiple critical vulnerabilities (CVE-2025-67862, CVE-2026-25089, CVE-2026-49938) have been discovered across Fortinet products including FortiOS, FortiPortal, FortiProxy, and FortiSandbox, enabling unauthenticated attackers to achieve remote arbitrary code execution and compromise data confidentiality.
date: "2026-06-14T09:12:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisandbox_paas:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - data-exfiltration
  - vulnerability
  - fortinet
  - network-appliance
vendors:
  - Fortinet
products:
  - FortiOS (versions 7.2.x antérieures à 7.2.11)
  - FortiOS (versions 7.4.x antérieures à 7.4.8)
  - FortiOS (versions 7.6.x antérieures à 7.6.3)
  - FortiPortal (versions 7.4.x antérieures à 7.4.8)
  - FortiPortal (versions antérieures à 7.2.9)
  - FortiProxy (versions 7.2.x antérieures à 7.2.15)
  - FortiProxy (versions 7.4.x antérieures à 7.4.11)
  - FortiProxy (versions 7.6.x antérieures à 7.6.4)
  - FortiSandbox Cloud (versions 5.0.4 et 5.0.5 antérieures à 5.0.6)
  - FortiSandbox PaaS (versions 5.0.4 et 5.0.5 antérieures à 5.0.6)
  - FortiSandbox (versions 4.4.x antérieures à 4.4.9)
  - FortiSandbox (versions 5.0.x antérieures à 5.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
cves:
  - id: CVE-2025-67862
    cvss: 6.7
    epss: 0.00012
  - id: CVE-2026-25089
    cvss: 9.8
    epss: 0.00898
  - id: CVE-2026-49938
    cvss: 6.5
    epss: 0.00032
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0725/
  - https://www.fortiguard.com/psirt/FG-IR-26-140
  - https://www.fortiguard.com/psirt/FG-IR-26-141
  - https://www.fortiguard.com/psirt/FG-IR-26-143
  - https://www.cve.org/CVERecord?id=CVE-2025-67862
  - https://www.cve.org/CVERecord?id=CVE-2026-25089
  - https://www.cve.org/CVERecord?id=CVE-2026-49938
iocs:
  - type: url
    value: https://www.fortiguard.com/psirt/FG-IR-26-140
  - type: url
    value: https://www.fortiguard.com/psirt/FG-IR-26-141
  - type: url
    value: https://www.fortiguard.com/psirt/FG-IR-26-143
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2025-67862
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-25089
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49938
ioc_counts:
  url: 6
rules:
  - title: Detects CVE-2026-25089/49938 Exploitation Attempts - Suspicious HTTP Request Patterns
    description: Detects HTTP requests containing common command injection or RCE patterns targeting web interfaces of Fortinet products, which could indicate exploitation attempts for CVE-2026-25089, CVE-2026-49938, or related RCE vulnerabilities.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1210
    data_sources:
      - webserver
  - title: Detects CVE-2025-67862 Exploitation Attempts - Unusual HTTP Access to Sensitive Paths
    description: Detects attempts to access unusual or sensitive file paths on Fortinet products via HTTP, which could indicate exploitation attempts for CVE-2025-67862 or similar data confidentiality vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1003.008
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 2
---

Multiple critical vulnerabilities (CVE-2025-67862, CVE-2026-25089, CVE-2026-49938) have been identified across various Fortinet products including FortiOS, FortiPortal, FortiProxy, and FortiSandbox. These flaws, detailed in Fortinet security bulletins FG-IR-26-140, FG-IR-26-141, and FG-IR-26-143 issued on June 9, 2026, could allow an unauthenticated attacker to achieve remote arbitrary code execution (RCE) and compromise data confidentiality. CERT-FR published an advisory (CERTFR-2026-AVI-0725) on June 10, 2026, urging immediate patching. The widespread deployment of Fortinet products in enterprise networks makes these vulnerabilities high-impact, as successful exploitation could lead to full system compromise, network breaches, and sensitive data exposure without prior authentication.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable Fortinet product (e.g., FortiOS, FortiPortal, FortiProxy, FortiSandbox) exposed to the internet.
2. The attacker crafts and sends a malicious HTTP request targeting the specific vulnerability (CVE-2025-67862, CVE-2026-25089, or CVE-2026-49938).
3. The vulnerable Fortinet product processes the malformed request, triggering the underlying vulnerability, potentially in a web-facing component.
4. Successful exploitation of RCE vulnerabilities (CVE-2026-25089, CVE-2026-49938) allows the attacker to execute arbitrary commands on the underlying operating system of the appliance.
5. With RCE, the attacker gains full control over the compromised Fortinet device, enabling them to establish persistence or deploy further malicious payloads.
6. The attacker can then use the compromised device as a pivot point to move laterally within the network or access sensitive data, leveraging data confidentiality vulnerabilities (CVE-2025-67862) to exfiltrate information.
7. The final objective could range from network reconnaissance, further system compromise, data theft, or disruption of network services.

## Impact

The identified vulnerabilities pose a critical risk to organizations utilizing affected Fortinet products. Successful exploitation, particularly of the RCE flaws, could lead to full compromise of the Fortinet appliance itself, granting attackers a foothold within the perimeter network. This could facilitate unauthorized access to internal systems, network segmentation bypasses, and the deployment of additional malware such as backdoors or ransomware. Data confidentiality breaches could result in the exposure of sensitive network configurations, user credentials, or other critical business data, potentially leading to significant financial loss, reputational damage, and regulatory penalties. The widespread use of Fortinet products globally means a broad array of organizations across various sectors could be susceptible.

## Recommendation

*   Immediately apply the security patches provided by Fortinet for all affected products listed in this brief (FortiOS < 7.2.11, FortiPortal < 7.4.8, FortiProxy < 7.2.15, FortiSandbox < 5.0.6, etc.) to address CVE-2025-67862, CVE-2026-25089, and CVE-2026-49938.
*   Deploy the provided Sigma rules "Detects CVE-2026-25089/49938 Exploitation Attempts - Suspicious HTTP Request Patterns" and "Detects CVE-2025-67862 Exploitation Attempts - Unusual HTTP Access to Sensitive Paths" to your SIEM to detect potential exploitation attempts.
*   Ensure web server logging is enabled and configured for detailed HTTP request information on all Fortinet devices to support detection via the Sigma rules.
*   Monitor network traffic for unusual outbound connections originating from Fortinet devices, especially after patching, as a potential indicator of prior compromise (referencing `network_connection` log source).
