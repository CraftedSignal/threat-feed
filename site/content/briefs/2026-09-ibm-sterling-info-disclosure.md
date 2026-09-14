---
title: Information Disclosure Vulnerability in IBM Sterling File Gateway
slug: 2026-09-ibm-sterling-info-disclosure
description: IBM Sterling File Gateway contains an improper access control vulnerability (CVE-2026-19290) that allows remote attackers to obtain sensitive information.
date: "2026-09-14T21:36:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:sterling_file_gateway:6.2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:sterling_file_gateway:6.2.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:sterling_file_gateway:6.2.2.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - information-disclosure
  - ibm
vendors:
  - IBM
products:
  - Sterling File Gateway (6.2.0.0 - 6.2.0.6_1, 6.2.1.0 - 6.2.1.2, 6.2.2.0 - 6.2.2.1)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A remote attacker could exploit this vulnerability to obtain sensitive data.
    confidence_band: high
cves:
  - id: CVE-2026-19290
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19290
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Patch IBM Sterling File Gateway to a version not listed in the affected range.
      owner: IT Operations
      addresses: CVE-2026-19290
      evidence: NVD vulnerability disclosure
---

IBM Sterling File Gateway is affected by a security vulnerability identified as CVE-2026-19290, which stems from improper access control mechanisms. The vulnerability exists within specific versions of the application, including 6.2.0.0 through 6.2.0.6_1, 6.2.1.0 through 6.2.1.2, and 6.2.2.0 through 6.2.2.1. This flaw permits a remote, unauthenticated attacker to bypass intended access restrictions and gain unauthorized access to sensitive information stored within the system. Given the nature of Sterling File Gateway as a secure file transfer solution, the exposure of data managed by this platform presents a significant risk to organizational confidentiality. The vulnerability carries a CVSS v3.1 base score of 7.5.

## Impact

Successful exploitation of this vulnerability allows remote attackers to access sensitive data managed by IBM Sterling File Gateway without proper authorization. Organizations utilizing the affected versions in their file transfer workflows are at risk of data exfiltration and loss of regulatory compliance.

## Recommendation

Prioritize the identification of all IBM Sterling File Gateway instances within the environment. Consult the official IBM security bulletin to obtain the patch release or security update that resolves CVE-2026-19290 for your specific deployment version. Ensure all internet-facing instances are restricted from unauthorized network access until the vendor-supplied patches are successfully applied.
