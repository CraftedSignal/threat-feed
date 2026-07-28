---
title: 'CVE-2026-8164: ArkSigner Desktop Client Vulnerable to Search Order Hijacking'
slug: 2026-07-arksigner-search-order-hijacking
description: An Uncontrolled Search Path Element vulnerability, CVE-2026-8164, in ArkSigner Desktop Client versions from v2.2.16.10 through 17062026 allows a local attacker to perform Search Order Hijacking, potentially leading to arbitrary code execution or privilege escalation with the application's privileges.
date: "2026-07-28T15:21:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - search-order-hijacking
  - dll-sideloading
  - privilege-escalation
  - local-exploitation
vendors:
  - ArkSigner Software and Hardware Industry and Trade Inc.
products:
  - ArkSigner Desktop Client (v2.2.16.10 through 17062026)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Uncontrolled Search Path Element vulnerability in ArkSigner Software and Hardware Industry and Trade Inc. ArkSigner Desktop Client allows Search Order Hijacking.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Uncontrolled Search Path Element vulnerability in ArkSigner Software and Hardware Industry and Trade Inc. ArkSigner Desktop Client allows Search Order Hijacking.
    confidence_band: high
cves:
  - id: CVE-2026-8164
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8164
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0665
---

A critical vulnerability, CVE-2026-8164, has been identified in ArkSigner Software and Hardware Industry and Trade Inc.'s ArkSigner Desktop Client, affecting versions from v2.2.16.10 up to and including 17062026. This vulnerability, categorized as an Uncontrolled Search Path Element (CWE-427), enables "Search Order Hijacking." This allows a local attacker to manipulate the application's search path, leading to the loading and execution of malicious code instead of legitimate application components. If exploited, an attacker could achieve arbitrary code execution or elevate privileges on the affected system, gaining control over the client's environment or compromising sensitive data. This is a local vulnerability, meaning an attacker would typically need prior access to the system or trick a user into executing a malicious payload to leverage this flaw.

## Attack Chain

1. **Initial Access**: An attacker gains local access to the victim's system, potentially through social engineering, exploitation of another vulnerability, or physical access.
2. **Vulnerability Identification**: The attacker identifies the vulnerable ArkSigner Desktop Client application and understands its susceptibility to Search Order Hijacking.
3. **Search Path Analysis**: The attacker analyzes the application's Dynamic Link Library (DLL) or executable search order to identify a user-writable directory that is searched before the legitimate system or application directories.
4. **Malicious Payload Creation**: A malicious DLL or executable is crafted, mimicking the name of a legitimate file the ArkSigner Desktop Client expects to load (e.g., a common system DLL).
5. **Payload Placement**: The attacker places the malicious file in the identified user-writable directory within the application's search path.
6. **Application Execution Trigger**: The user launches the vulnerable ArkSigner Desktop Client, or the attacker triggers its execution.
7. **Malicious Code Execution**: Due to the compromised search order, the ArkSigner Desktop Client loads and executes the attacker's malicious DLL/executable.
8. **Impact**: The malicious code executes with the privileges of the ArkSigner Desktop Client, potentially leading to privilege escalation, arbitrary code execution, persistence mechanisms, or further compromise of the system.

## Impact

Successful exploitation of CVE-2026-8164 could grant an attacker the ability to execute arbitrary code with the privileges of the ArkSigner Desktop Client. This could lead to local privilege escalation, allowing an attacker to gain higher access rights on the compromised system. Consequences may include full system compromise, installation of backdoors, data exfiltration, or the deployment of additional malware such as ransomware. While specific victim counts or targeted sectors are not detailed, any organization or individual using the affected ArkSigner Desktop Client versions is at risk, as the vulnerability resides in a commonly used desktop application.

## Recommendation

* Immediately apply patches or updates for ArkSigner Desktop Client to address CVE-2026-8164, as provided by ArkSigner Software and Hardware Industry and Trade Inc.
* Restrict user permissions to prevent non-administrative users from writing to critical system directories or common application search paths where malicious DLLs could be placed.
* Implement application whitelisting solutions to prevent the execution of unauthorized binaries, especially in directories susceptible to Search Order Hijacking.
* Monitor process creation events and DLL load events on systems running ArkSigner Desktop Client for unusual activity, such as executables loading DLLs from unexpected paths.
