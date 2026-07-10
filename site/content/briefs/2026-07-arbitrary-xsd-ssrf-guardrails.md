---
title: Arbitrary XML Schema Definition Processing in guardrails-detectors Leads to SSRF and Local File Read
slug: 2026-07-arbitrary-xsd-ssrf-guardrails
description: A flaw in the 'file_type' content detector of 'guardrails-detectors' allows a remote attacker to provide an arbitrary XML Schema Definition (XSD) string, leading to server-side request forgery (SSRF) and local file reads, potentially exposing sensitive information such as cloud provider credentials or granting access to internal network services.
date: "2026-07-10T16:18:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - ssrf
  - local-file-read
  - info-disclosure
  - guardrails
vendors:
  - Guardrails
products:
  - guardrails-detectors
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a remote attacker to supply an arbitrary XML Schema Definition (XSD) string, which is processed without proper restrictions.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: local file reads, potentially resulting in sensitive information disclosure, such as cloud provider credentials
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: access to internal network services
    confidence_band: high
cves:
  - id: CVE-2026-15143
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15143
---

A critical vulnerability, tracked as CVE-2026-15143, has been identified in the `file_type` content detector component of `guardrails-detectors`. This flaw enables a remote attacker to supply an arbitrary XML Schema Definition (XSD) string, which the affected software processes without adequate validation or restrictions. Successful exploitation of this vulnerability can result in severe consequences, including Server-Side Request Forgery (SSRF) and the ability to perform local file reads. This exposure can lead to the disclosure of highly sensitive information, such as cloud provider credentials, API keys, or proprietary data stored on the system. Furthermore, the SSRF capability could allow attackers to bypass network segmentation and gain unauthorized access to internal network services, escalating the attack to other systems within the compromised environment.

## Attack Chain

1. A remote attacker crafts a malicious XML Schema Definition (XSD) string designed to trigger either Server-Side Request Forgery (SSRF) or local file read primitives.
2. The attacker delivers this crafted XSD string as input to the `file_type` content detector within the vulnerable `guardrails-detectors` component.
3. The `guardrails-detectors` component processes the arbitrary XSD string without proper restrictions, enabling the embedded malicious directives.
4. The exploitation results in the `guardrails-detectors` system initiating unauthorized server-side requests to internal or external arbitrary URLs (SSRF).
5. Concurrently or alternatively, the exploitation allows the attacker to read arbitrary local files from the compromised system.
6. Through local file reads, the attacker exfiltrates sensitive information such as cloud provider credentials, configuration files, or other sensitive data.
7. Leveraging the SSRF capabilities, the attacker gains unauthorized access to internal network services, potentially facilitating lateral movement or further information disclosure within the network.

## Impact

Successful exploitation of CVE-2026-15143 carries a CVSS v3.1 Base Score of 9.3, indicating critical severity. The primary impact involves sensitive information disclosure, potentially compromising crucial assets such as cloud provider credentials. This can grant attackers unauthorized access to cloud resources, leading to data breaches, resource manipulation, or further attacks on cloud infrastructure. Additionally, the ability to read local files allows attackers to steal proprietary data, configuration files, or user information directly from the server. The Server-Side Request Forgery (SSRF) aspect enables attackers to bypass network perimeter defenses, access internal network services, scan internal networks, or interact with other internal systems, significantly broadening the scope of potential damage and facilitating deeper penetration into the target environment.

## Recommendation

* Patch CVE-2026-15143 on all affected `guardrails-detectors` installations immediately to prevent remote exploitation.
* Implement strong egress filtering to restrict outbound connections from `guardrails-detectors` instances to only necessary and approved destinations, mitigating the impact of potential SSRF exploits.
* Monitor network logs for suspicious outbound connections originating from the `guardrails-detectors` application to unusual or internal IP addresses that align with potential SSRF activity.
* Implement file integrity monitoring on critical files (e.g., configuration files, credential stores) accessed by `guardrails-detectors` to detect unauthorized local file reads.
