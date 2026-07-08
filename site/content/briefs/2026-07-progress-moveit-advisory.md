---
title: Progress MOVEit Transfer Critical Security Advisory (AV26-678)
slug: 2026-07-progress-moveit-advisory
description: Progress Software has issued a critical security advisory (AV26-678) detailing multiple vulnerabilities, including CVE-2026-10699, CVE-2026-10698, and CVE-2026-11903, affecting various versions of its MOVEit Transfer product, necessitating immediate patching to prevent potential exploitation.
date: "2026-07-08T20:05:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - data-exfiltration
  - critical-vulnerability
  - moveit
vendors:
  - Progress
products:
  - MOVEit Transfer (<= 2024.1.8)
  - MOVEit Transfer (2025.0.0-2025.0.7)
  - MOVEit Transfer (2025.1.0-2025.1.3)
  - MOVEit Transfer (2026.0.0)
cves:
  - id: CVE-2026-10699
    cvss: 7.5
  - id: CVE-2026-10698
    cvss: 7.2
  - id: CVE-2026-11903
    cvss: 8
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-security-advisory-av26-678
  - https://community.progress.com/s/article/MOVEit-Transfer-Critical-Security-Bulletin-June-2026
---

On July 8, 2026, the Canadian Centre for Cyber Security (CCCS) issued an alert, AV26-678, referencing a critical security bulletin from Progress Software. This advisory addresses multiple severe vulnerabilities (CVE-2026-10699, CVE-2026-10698, CVE-2026-11903) impacting MOVEit Transfer, a widely used managed file transfer solution. Affected versions include 2024.1.8 and prior, 2025.0.0 to 2025.0.7, 2025.1.0 to 2025.1.3, and 2026.0.0. While specific exploitation details are not provided in the advisory, critical vulnerabilities in such systems typically pose a significant risk of unauthorized access, data exfiltration, or remote code execution, making immediate patching crucial for all organizations utilizing MOVEit Transfer.

## Attack Chain

The provided security advisories (AV26-678, CVE-2026-10699, CVE-2026-10698, CVE-2026-11903) from Progress Software and the CCCS do not detail specific exploitation methods or a step-by-step attack chain for these vulnerabilities. However, unpatched critical vulnerabilities in managed file transfer solutions can broadly lead to the following outcomes:

1. **Vulnerability Identification:** An attacker identifies an unpatched MOVEit Transfer instance on an internet-facing network.
2. **Initial Access:** The attacker exploits one of the identified critical vulnerabilities (e.g., CVE-2026-10699, CVE-2026-10698, CVE-2026-11903) to gain unauthorized access to the MOVEit Transfer server. This could involve bypassing authentication, injecting malicious code, or leveraging flaws in file processing.
3. **Command Execution / Data Access:** Upon successful exploitation, the attacker gains the ability to execute arbitrary commands on the underlying server or access sensitive files stored within the MOVEit Transfer environment.
4. **Data Exfiltration:** Malicious actors may then search for and exfiltrate sensitive data, such as customer records, financial information, or intellectual property, to attacker-controlled infrastructure.
5. **Persistence (Optional):** The attacker might establish persistence mechanisms on the compromised server to maintain access even if initial vulnerabilities are patched later.
6. **Impact:** The final objective is typically data theft, disruption of services, or further lateral movement into the victim's network.

## Impact

The impact of unpatched critical vulnerabilities in MOVEit Transfer is severe, as the product is designed to handle and transfer sensitive data for organizations across various sectors. Successful exploitation could lead to unauthorized access to an organization's most critical data, resulting in massive data breaches, significant financial losses due and regulatory fines, reputational damage, and operational disruption. While the current advisory does not provide victim counts or specific sectors targeted, past incidents involving MOVEit Transfer vulnerabilities have affected hundreds of organizations globally, including government agencies, financial institutions, and healthcare providers, underscoring the widespread potential for devastating consequences.

## Recommendation

* Immediately review the Progress Security Bulletin linked in this brief and apply the necessary updates to all affected MOVEit Transfer instances to address CVE-2026-10699, CVE-2026-10698, and CVE-2026-11903.
* Validate that all MOVEit Transfer versions listed in the advisory are updated to their respective patched versions.
* Consult the CCCS advisory (AV26-678) for additional guidance and stay informed on subsequent updates from Progress Software.
