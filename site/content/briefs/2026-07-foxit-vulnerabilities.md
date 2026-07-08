---
title: Multiple Vulnerabilities in Foxit PDF Editor and Reader
slug: 2026-07-foxit-vulnerabilities
description: Multiple critical vulnerabilities, including CVE-2026-13126 and CVE-2026-13127, have been discovered in Foxit PDF Editor and Reader for Windows and macOS, enabling a remote attacker to achieve arbitrary code execution, elevate privileges, and compromise data confidentiality if users open a crafted malicious PDF document.
date: "2026-07-08T14:13:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - client-side-exploitation
  - document-exploit
  - pdf
  - rce
  - privilege-escalation
  - data-exfiltration
  - windows
  - macos
vendors:
  - Foxit
products:
  - PDF Editor (< 13.2.5)
  - PDF Editor (< 14.0.5)
  - PDF Editor (< 2026.1.2)
  - PDF Reader (< 2026.1.2)
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer [...] une élévation de privilèges
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer [...] une atteinte à la confidentialité des données.
    confidence_band: high
cves:
  - id: CVE-2026-57249
    cvss: 7.8
  - id: CVE-2026-57251
    cvss: 7.8
  - id: CVE-2026-57255
    cvss: 6.1
  - id: CVE-2026-57256
    cvss: 7.8
  - id: CVE-2026-57257
    cvss: 6.1
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0845/
  - https://www.foxitsoftware.com/support/security-bulletins.php
  - https://www.cve.org/CVERecord?id=CVE-2026-13126
  - https://www.cve.org/CVERecord?id=CVE-2026-13127
  - https://www.cve.org/CVERecord?id=CVE-2026-13128
  - https://www.cve.org/CVERecord?id=CVE-2026-13129
  - https://www.cve.org/CVERecord?id=CVE-2026-57237
  - https://www.cve.org/CVERecord?id=CVE-2026-57238
  - https://www.cve.org/CVERecord?id=CVE-2026-57239
  - https://www.cve.org/CVERecord?id=CVE-2026-57240
  - https://www.cve.org/CVERecord?id=CVE-2026-57241
  - https://www.cve.org/CVERecord?id=CVE-2026-57242
  - https://www.cve.org/CVERecord?id=CVE-2026-57243
  - https://www.cve.org/CVERecord?id=CVE-2026-57244
  - https://www.cve.org/CVERecord?id=CVE-2026-57245
  - https://www.cve.org/CVERecord?id=CVE-2026-57246
  - https://www.cve.org/CVERecord?id=CVE-2026-57247
  - https://www.cve.org/CVERecord?id=CVE-2026-57248
  - https://www.cve.org/CVERecord?id=CVE-2026-57249
  - https://www.cve.org/CVERecord?id=CVE-2026-57250
  - https://www.cve.org/CVERecord?id=CVE-2026-57251
  - https://www.cve.org/CVERecord?id=CVE-2026-57252
  - https://www.cve.org/CVERecord?id=CVE-2026-57253
  - https://www.cve.org/CVERecord?id=CVE-2026-57254
  - https://www.cve.org/CVERecord?id=CVE-2026-57255
  - https://www.cve.org/CVERecord?id=CVE-2026-57256
  - https://www.cve.org/CVERecord?id=CVE-2026-57257
  - https://www.cve.org/CVERecord?id=CVE-2026-57258
  - https://www.cve.org/CVERecord?id=CVE-2026-57259
  - https://www.cve.org/CVERecord?id=CVE-2026-57260
---

CERT-FR has issued an advisory regarding multiple critical vulnerabilities affecting Foxit PDF Editor and Reader products across both Windows and macOS platforms, initially identified on July 8, 2026. These vulnerabilities, including a range of CVEs such as CVE-2026-13126 through CVE-2026-13129 and CVE-2026-57237 through CVE-2026-57260, could be exploited by a remote attacker. The exploitation of these flaws could lead to severe consequences for affected users, including arbitrary code execution, unauthorized privilege escalation, and significant data confidentiality breaches. These vulnerabilities affect specific versions of PDF Editor (prior to 13.2.5, 14.0.5, and 2026.1.2) and PDF Reader (prior to 2026.1.2). For defenders, this means immediate patching of all vulnerable Foxit installations is crucial to prevent client-side compromise.

## Attack Chain

1. **Initial Access**: An attacker crafts a malicious PDF document designed to exploit one or more of the vulnerabilities (e.g., CVE-2026-13126). This document is typically delivered to a victim via email as an attachment or through a compromised website.
2. **User Interaction**: The victim is enticed to open the malicious PDF document using their vulnerable Foxit PDF Editor or Reader application.
3. **Vulnerability Trigger**: Upon opening the document, the parsing engine of the Foxit application encounters the malformed or specially crafted content within the PDF, triggering the underlying vulnerability (e.g., a heap buffer overflow, out-of-bounds write).
4. **Arbitrary Code Execution**: Successful exploitation of the vulnerability leads to arbitrary code execution within the context of the vulnerable Foxit application, allowing the attacker to run their own malicious code.
5. **Privilege Escalation**: If the initial code execution occurs in a low-privileged user context, the attacker may then leverage an additional privilege escalation vulnerability (e.g., CVE-2026-13128) to gain higher system privileges, such as SYSTEM on Windows or root on macOS.
6. **Post-Exploitation**: With elevated privileges, the attacker can establish persistence, install additional malware (e.g., ransomware, wipers), exfiltrate sensitive data (e.g., CVE-2026-13129), or further compromise the affected system and potentially the network.

## Impact

The successful exploitation of these numerous vulnerabilities can result in significant damage to an organization. Attackers can gain complete control over a user's workstation through arbitrary code execution, potentially leading to the deployment of ransomware or other destructive malware across the network. Privilege escalation allows an attacker to bypass security controls and access sensitive system resources. Furthermore, compromised data confidentiality can lead to the theft of intellectual property, personal identifiable information (PII), and other critical business data, incurring regulatory fines, reputational damage, and severe financial losses. While no specific victim counts or targeted sectors are mentioned, any organization utilizing vulnerable Foxit products is at risk.

## Recommendation

* Prioritize patching all affected Foxit products immediately by applying updates from the vendor's security bulletin at `https://www.foxitsoftware.com/support/security-bulletins.php`.
* Ensure Foxit PDF Editor versions are updated to at least 13.2.5, 14.0.5, or 2026.1.2, and Foxit PDF Reader versions are updated to at least 2026.1.2.
* Educate users on the risks of opening suspicious or untrusted PDF documents delivered via email or downloaded from unknown sources, as this is the likely initial access vector for CVE-2026-13126, CVE-2026-13127, CVE-2026-13128, CVE-2026-13129, and others.
