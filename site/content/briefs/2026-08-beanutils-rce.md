---
title: Apache Commons BeanUtils Information Leak and RCE Chain
slug: 2026-08-beanutils-rce
description: CVE-2025-48734 enables attackers to enumerate the Java classpath and ClassLoader via property injection, facilitating RCE when chained with unsafe deserialization endpoints.
date: "2026-08-25T22:00:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:commons_beanutils:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_beanutils:2.0.0:milestone1:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Commons Beanutils
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An attacker who can control the property path... can obtain a reference to the application's ClassLoader and enumerate all JARs.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2025-48734 affects Apache Commons BeanUtils... RCE chain when combined with an unsafe Java deserialization endpoint.
    confidence_band: high
cves:
  - id: CVE-2025-48734
    cvss: 8.8
    epss: 0.01699
references:
  - https://github.com/advisories/GHSA-wxr5-93ph-8wr9
  - https://github.com/frohoff/ysoserial
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-H3RAKLEZ-CVE-2025-48734
rules:
  - title: Detect CVE-2025-48734 Exploitation Attempt - Property Access
    description: Detects suspicious access to 'declaringClass' or 'classLoader' properties via web application endpoints.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Apache Commons Beanutils in all production Java applications
      owner: IT Operations
      due: 72h
      evidence: Mitigation section confirms patching is required
  mitigation_plan:
    - priority: immediate
      action: Deploy ObjectInputFilter to restrict deserialization
      owner: Security Engineering
      addresses: RCE delivery vector
      evidence: Mitigation section provides configuration example
---

CVE-2025-48734 affects Apache Commons BeanUtils versions prior to 1.11.0 (and 2.0.0-M2), allowing unauthenticated attackers to access the 'declaringClass' property of Java enums. By exploiting PropertyUtilsBean to access nested properties like 'enum.declaringClass.classLoader', an attacker can leak the application's ClassLoader. This vulnerability does not provide RCE directly; however, it functions as a critical reconnaissance pivot for identifying vulnerable gadget libraries (e.g., Commons Collections 3.x) within the classpath. When an application also exposes an unsafe Java deserialization endpoint, this information leak allows an attacker to reliably trigger an RCE chain. The vulnerability is highly relevant to enterprise environments utilizing legacy Java applications or shared middleware.

## Attack Chain

1. Attacker identifies an endpoint accepting property path inputs processed by PropertyUtilsBean (e.g., /api/property?path=...).
2. Attacker injects a malicious property path targeting 'status.declaringClass' to verify access to the enum internal class.
3. Attacker pivots to 'status.declaringClass.classLoader' to obtain a reference to the application ClassLoader.
4. Attacker iterates through the ClassLoader URL array to enumerate all loaded JAR files, identifying presence of vulnerable gadget libraries like Commons Collections 3.2.2.
5. Attacker fuzzes application endpoints (e.g., /api/data/import) to identify a target supporting Java deserialization by sending the '0xACED0005' magic header.
6. Attacker utilizes ysoserial to generate a gadget-based payload (e.g., CommonsCollections6) specific to the identified environment.
7. Attacker delivers the serialized payload via HTTP POST to the identified deserialization endpoint.
8. Remote code execution occurs during the object reconstruction process, executing the attacker-provided command on the target host.

## Impact

Successful exploitation leads to full remote code execution, granting the attacker arbitrary command execution capabilities with the privileges of the web application service account. This allows for total system compromise, data exfiltration, or lateral movement within the network. The vulnerability impacts any application using affected versions of Apache Commons BeanUtils that exposes property path manipulation combined with unsafe deserialization.

## Recommendation

* Upgrade Apache Commons BeanUtils to version 1.11.0 or 2.0.0-M2 immediately to patch CVE-2025-48734.
* Implement strict Java ObjectInputFilter controls on all deserialization endpoints to permit only necessary classes.
* Audit application code for usage of PropertyUtilsBean where the 'path' parameter is derived from untrusted user input.
* Use the CVE-2025-48734 remediation to prevent classpath enumeration reconnaissance, breaking the RCE chain at the initial discovery phase.
