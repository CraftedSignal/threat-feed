---
title: Vulnerability in Schneider Electric EcoStruxure IT Data Center Expert Leads to Data Confidentiality Compromise (CVE-2026-8045)
slug: 2026-06-schneider-ecostruxure-data-confidentiality
description: A critical vulnerability, CVE-2026-8045, has been identified in Schneider Electric EcoStruxure IT Data Center Expert versions prior to 9.1.2, allowing an attacker to achieve unauthorized access to sensitive data and compromise its confidentiality.
date: "2026-06-14T09:08:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - scada
  - ics
  - data-confidentiality
  - information-disclosure
vendors:
  - Schneider Electric
products:
  - EcoStruxure IT Data Center Expert (< 9.1.2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8045
    epss: 0.00057
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0713/
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-160-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-160-01.pdf
  - https://www.cve.org/CVERecord?id=CVE-2026-8045
rules:
  - title: Detect CVE-2026-8045 Exploitation Attempt - Sensitive Web Path Access
    description: Detects attempts to access common sensitive web paths that could indicate an information disclosure or path traversal exploitation attempt of CVE-2026-8045 in Schneider Electric EcoStruxure IT DCE.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
  - title: Detect Large Outbound Network Connections from EcoStruxure IT DCE
    description: Detects unusually large volumes of outbound network data from a host running Schneider Electric EcoStruxure IT Data Center Expert, potentially indicating post-exploitation data exfiltration after a CVE-2026-8045 compromise.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
      - T1048
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CERT-FR has issued an advisory regarding a significant vulnerability, CVE-2026-8045, discovered in Schneider Electric EcoStruxure IT Data Center Expert products. This flaw affects all versions prior to 9.1.2 and enables an attacker to compromise the confidentiality of data stored or processed by the system. EcoStruxure IT Data Center Expert is a critical management software for data center infrastructure, meaning a breach could expose sensitive operational data, configurations, or even credentials. The vulnerability's exact technical details are not publicly disclosed, but its impact on data confidentiality necessitates immediate patching to mitigate the risk of unauthorized information access and potential exfiltration by malicious actors.

## Attack Chain

1.  An attacker identifies a Schneider Electric EcoStruxure IT Data Center Expert instance accessible via the network, potentially through passive reconnaissance.
2.  The attacker determines the target system is running a vulnerable version prior to 9.1.2.
3.  The attacker leverages CVE-2026-8045 by sending specially crafted network requests or inputs to the EcoStruxure IT DCE service.
4.  Successful exploitation of the vulnerability bypasses existing access controls or triggers an information disclosure flaw.
5.  The attacker gains unauthorized access to internal files, databases, or configuration parameters containing sensitive information on the EcoStruxure IT DCE server.
6.  The attacker enumerates and discovers confidential data, which may include operational settings, device credentials, or network topology information.
7.  The attacker extracts or views the identified sensitive data, leading to a breach of data confidentiality.

## Impact

The successful exploitation of CVE-2026-8045 directly results in a data confidentiality breach. For organizations utilizing EcoStruxure IT Data Center Expert, this means an attacker could gain unauthorized access to critical data center information, such as device configurations, passwords, operational metrics, and potentially sensitive customer data. Such exposure could lead to further network compromise, intellectual property theft, regulatory fines, reputational damage, and operational disruption. The advisory does not specify observed victim numbers or targeted sectors, but any organization using affected versions is at risk.

## Recommendation

*   Immediately update Schneider Electric EcoStruxure IT Data Center Expert installations to version 9.1.2 or higher as recommended in the Schneider Electric bulletin (SEVD-2026-160-01).
*   Monitor network connections originating from EcoStruxure IT Data Center Expert systems for unusual outbound traffic patterns, especially large data transfers, using rules like "Detect Large Outbound Network Connections from EcoStruxure IT DCE".
*   Implement robust network segmentation to restrict direct exposure of EcoStruxure IT Data Center Expert instances, reducing the attack surface for CVE-2026-8045.
