---
title: Remote Code Execution in Digiwin EasyFlow .NET via Insecure Deserialization
slug: 2026-09-easyflow-deserialization
description: Digiwin EasyFlow .NET is vulnerable to an insecure deserialization flaw, enabling unauthenticated remote attackers to achieve arbitrary code execution via crafted serialized input.
date: "2026-09-30T10:33:58Z"
lastmod: "2026-09-30T10:34:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:digiwin:easyflow_.net:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - deserialization
  - web-application
  - vulnerability
  - rce
vendors:
  - Digiwin
products:
  - EasyFlow .NET
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can execute arbitrary code on the server by sending maliciously crafted serialized content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Unauthenticated remote attackers can execute arbitrary code on the server
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: upload and execute web shell backdoors
    confidence_band: high
cves:
  - id: CVE-2026-102455
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102455
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102454
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch CVE-2026-102455 on all Digiwin EasyFlow .NET instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-102455 NVD advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to EasyFlow .NET web interfaces
      owner: SOC
      addresses: CVE-2026-102455
      evidence: NVD vulnerability severity
updates:
  - at: "2026-09-30T10:34:11Z"
    level: L2
    summary: added coverage for EasyFlow .NET
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102454
---

Digiwin EasyFlow .NET contains a critical security vulnerability (CVE-2026-102455) arising from improper deserialization of untrusted data. An unauthenticated, remote attacker can exploit this flaw by sending a specially crafted serialized payload to the affected application. Successful exploitation results in remote code execution (RCE) with the privileges of the web service account. Given the nature of deserialization vulnerabilities in .NET applications, this typically occurs when the application uses insecure formatter settings or fails to validate object types during the deserialization process. This threat is particularly significant for enterprise environments using EasyFlow .NET for workflow management, as it provides a direct path for attackers to gain full control over the application server without prior authentication.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code on the underlying host server. This can lead to full system compromise, exfiltration of sensitive organizational data, lateral movement within the network, or the deployment of additional malicious payloads such as ransomware. The high CVSS score of 9.8 reflects the ease of access and the severity of the potential impact on affected enterprise deployments.

## Recommendation

* Immediately isolate internet-facing EasyFlow .NET servers until patches are applied.
* Monitor web server logs for HTTP requests containing large or obfuscated base64-encoded blobs, which are often indicative of serialized .NET object delivery.
* Audit web server service accounts to ensure they operate with the principle of least privilege, limiting the potential impact of successful RCE.
* Engage with the Digiwin vendor support channel to obtain and apply the specific security update addressing CVE-2026-102455.
