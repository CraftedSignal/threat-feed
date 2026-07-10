---
title: Critical Blind SSRF Vulnerability in guardrails-detectors (CVE-2026-15378)
slug: 2026-07-guardrails-detectors-ssrf
description: A critical blind Server-Side Request Forgery (SSRF) vulnerability, CVE-2026-15378, exists in the `guardrails-detectors` component, allowing a remote attacker to exploit specially crafted XML Schema Definition (XSD) strings to gain unauthorized access to sensitive information from cloud metadata services, Kubernetes API, internal MinIO, and facilitate local file reads of service account tokens and pod secrets.
date: "2026-07-10T10:18:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - vulnerability
  - cloud
  - kubernetes
  - data-exfiltration
products:
  - guardrails-detectors
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability allows a remote attacker to perform a blind Server-Side Request Forgery (SSRF) by submitting a specially crafted XML Schema Definition (XSD) string.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation for Defense Evasion
    evidence: A flaw was found in the `guardrails-detectors` component. This vulnerability allows a remote attacker to perform a blind Server-Side Request Forgery (SSRF).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: Additionally, it enables local file reads of critical data such as service account tokens and pod secrets.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: unauthorized access to sensitive information, including credentials from cloud metadata services, Kubernetes API, internal MinIO, and other internal network endpoints.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Additionally, it enables local file reads of critical data such as service account tokens and pod secrets.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1538
    technique_name: Cloud API
    evidence: unauthorized access to sensitive information, including credentials from cloud metadata services, Kubernetes API
    confidence_band: high
cves:
  - id: CVE-2026-15378
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15378
---

A critical vulnerability, tracked as CVE-2026-15378, has been identified in the `guardrails-detectors` component. This flaw enables a remote attacker to initiate a blind Server-Side Request Forgery (SSRF) by submitting a meticulously crafted XML Schema Definition (XSD) string. The vulnerability has a CVSS v3.1 Base Score of 9.3, highlighting its severe impact. Successful exploitation can lead to unauthorized access to highly sensitive information, including credentials exposed by cloud metadata services, the Kubernetes API, and internal MinIO instances. Furthermore, it allows for the reading of critical local files, such as service account tokens and pod secrets, potentially compromising the integrity and confidentiality of the affected systems and their associated cloud or containerized environments. This vulnerability presents a significant risk for data exfiltration and privilege escalation within targeted infrastructures.

## Attack Chain

1. A remote attacker identifies an exposed instance of the `guardrails-detectors` component.
2. The attacker crafts a malicious XML Schema Definition (XSD) string designed to perform an SSRF, potentially embedding external entity references or other payload types.
3. The attacker submits this specially crafted XSD string to the vulnerable `guardrails-detectors` component.
4. Upon processing the XSD, the component initiates an outbound HTTP request (blind SSRF) to an arbitrary internal network endpoint or local file path specified by the attacker, without returning the response directly to the attacker.
5. Through the SSRF, the attacker gains unauthorized access to internal services, including cloud metadata services, Kubernetes API endpoints, or internal MinIO storage.
6. The vulnerability also allows for local file reads, enabling the attacker to retrieve sensitive files such as service account tokens and pod secrets from the compromised host.
7. The attacker infers the success of the SSRF requests and potentially exfiltrates collected sensitive data through out-of-band communication or by triggering specific error conditions.

## Impact

Successful exploitation of CVE-2026-15378 results in severe compromise of system confidentiality and potential integrity. Attackers can gain unauthorized access to credentials from cloud metadata services, which can lead to further compromise of cloud resources. Access to the Kubernetes API allows for control over containerized environments, potentially leading to container escape, privilege escalation, or deployment of malicious workloads. Compromising internal MinIO instances can expose large volumes of sensitive data. Additionally, local file reads of service account tokens and pod secrets grant attackers critical authentication material, facilitating lateral movement and persistent access. The blind nature of the SSRF makes detection challenging, increasing the window of opportunity for attackers to cause significant damage, including data theft and disruption of critical services.

## Recommendation

* Patch CVE-2026-15378 immediately in all `guardrails-detectors` components to remediate the blind SSRF vulnerability.
* Monitor network outbound connections from `guardrails-detectors` components for unusual requests to internal IP addresses or metadata endpoints, indicating potential SSRF exploitation attempts related to CVE-2026-15378.
* Implement strong network segmentation to limit the blast radius of successful SSRF attacks, preventing access to critical internal services like Kubernetes API, cloud metadata services, and MinIO.
* Restrict permissions for the `guardrails-detectors` component to the absolute minimum necessary, following the principle of least privilege, to mitigate the impact of local file read exploits linked to CVE-2026-15378.
