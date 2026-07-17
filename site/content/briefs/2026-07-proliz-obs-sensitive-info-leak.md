---
title: Proliz OBS Vulnerability Allows Sensitive Information Insertion Leading to ACL Bypass (CVE-2026-7189)
slug: 2026-07-proliz-obs-sensitive-info-leak
description: A high-severity vulnerability, CVE-2026-7189, in Proliz Software Ltd. Co.'s Proliz OBS before version 3.6.0 allows for the insertion of sensitive information into sent data, enabling attackers to access functionality not properly constrained by Access Control Lists (ACLs).
date: "2026-07-17T13:21:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - sensitive-data-exposure
  - access-control-bypass
vendors:
  - Proliz Software Ltd. Co.
products:
  - Proliz's OBS
cves:
  - id: CVE-2026-7189
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7189
---

A vulnerability, identified as CVE-2026-7189, exists in Proliz Software Ltd. Co.'s Proliz OBS software, specifically in versions prior to 3.6.0. This critical flaw involves the improper insertion of sensitive information into sent data, which an attacker can leverage to access functionality that should otherwise be protected by Access Control Lists (ACLs). With a CVSS v3.1 Base Score of 8.2 (High), this vulnerability poses a significant risk. Although specific attack vectors are not detailed, successful exploitation could lead to unauthorized access to restricted areas or data within the application, compromising confidentiality and potentially integrity of the system. Defenders need to prioritize patching to prevent malicious actors from bypassing access controls and gaining unauthorized capabilities within the OBS platform.

## Impact

If exploited, CVE-2026-7189 could allow an unauthorized attacker to bypass access control mechanisms in Proliz OBS, gaining access to sensitive data or functionality that should be restricted. This could lead to a compromise of data confidentiality and integrity, potentially enabling malicious operations within the application. The lack of proper ACL enforcement means an attacker could perform actions typically reserved for privileged users, leading to significant system compromise and unauthorized data manipulation or exposure. The exact scope of data exposed or functions accessible would depend on the specific configuration and sensitive data present within the affected Proliz OBS instance.

## Recommendation

* Patch CVE-2026-7189 on all affected Proliz OBS instances immediately by updating to version 3.6.0 or later as described in the reference materials.
* Review Access Control Lists (ACLs) within Proliz OBS for any signs of unauthorized modification or unusual access patterns post-patching.
