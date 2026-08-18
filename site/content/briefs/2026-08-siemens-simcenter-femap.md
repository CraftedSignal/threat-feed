---
title: Arbitrary Code Execution in Siemens Simcenter Femap
slug: 2026-08-siemens-simcenter-femap
description: Siemens Simcenter Femap is susceptible to arbitrary code execution via two out-of-bounds read vulnerabilities when parsing specially crafted BMP files.
date: "2026-08-13T16:53:08Z"
lastmod: "2026-08-18T17:49:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - industrial-control-systems
  - ics
  - cve-2026-59086
  - stack-overflow
  - rce
vendors:
  - Siemens
products:
  - Simcenter Femap
  - Simcenter Nastran
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: If a user is tricked to open a malicious file with the affected application, this could lead the application to crash or potentially lead to arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: If a user is tricked to run one of the impacted application binary with a malicious string, an attacker could leverage the vulnerability to perform remote code execution in the context of the current process.
    confidence_band: high
cves:
  - id: CVE-2026-59700
    cvss: 7.8
    epss: 0.00113
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-11
  - https://www.cve.org/CVERecord?id=CVE-2026-59700
  - https://www.cve.org/CVERecord?id=CVE-2026-59701
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-230-02
  - https://www.cve.org/CVERecord?id=CVE-2026-59086
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all instances of Siemens Simcenter Femap to V2606.0001
      owner: IT Operations
      due: 72h
      evidence: Vendor recommendation for remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict the ability of engineering workstations to open untrusted external files
      owner: Security Operations
      addresses: CVE-2026-59700, CVE-2026-59701
      evidence: General mitigation advice for file parsing vulnerabilities
updates:
  - at: "2026-08-18T17:49:22Z"
    level: L2
    summary: added coverage for Simcenter Femap +1 products
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-230-02
---

Siemens Simcenter Femap versions prior to V2606.0001 contain two vulnerabilities, CVE-2026-59700 and CVE-2026-59701, stemming from improper file parsing of BMP format images. These flaws are classified as out-of-bounds read vulnerabilities (CWE-125). An attacker can exploit these issues by providing a user with a specially crafted BMP file. If the victim opens the malicious file using the affected software, the application may crash or execute arbitrary code in the context of the user process. These vulnerabilities carry a CVSS score of 7.8 and are particularly relevant to the Critical Manufacturing sector where Simcenter Femap is deployed for engineering simulation tasks.

## Impact

Successful exploitation allows for remote code execution within the security context of the user running the software, potentially leading to unauthorized data access, system disruption, or further compromise of engineering workstations. The impact is categorized as high given the potential for full compromise of the local application process.

## Recommendation

* Immediately update Siemens Simcenter Femap to version V2606.0001 or later to remediate CVE-2026-59700 and CVE-2026-59701.
* Implement file access controls and restrict the opening of untrusted files within engineering environments to mitigate the risk of user-driven exploitation.
* Audit endpoint software to identify legacy installations of Siemens Simcenter Femap that require patching.
