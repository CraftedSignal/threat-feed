---
title: Active Exploitation of SQL Injection in Cisco Secure Email Gateway
slug: 2026-09-cisco-sql-injection
description: Cisco has confirmed active exploitation of a SQL injection vulnerability (CVE-2026-76461) affecting multiple versions of Cisco Secure Email Gateway and Secure Email and Web Manager products.
date: "2026-09-15T07:02:16Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - cve
  - network
  - active-exploitation
vendors:
  - Cisco
products:
  - Cisco AsyncOS for Cisco Secure Email Gateway (< 15.5.5-014, < 16.0.4-302, < 16.5.0-780)
  - Cisco Secure Email Gateway (< 15.5.5-014, < 16.5.0-780)
  - Cisco Secure Email and Web Manager (< 15.5.5-006, < 16.5.0-429)
cves:
  - id: CVE-2026-76461
    cvss: 9.8
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-76461
  - https://cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-921
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade affected Cisco Secure Email Gateway and Manager instances to fixed versions per advisory
      owner: IT Operations
      due: 24h
      evidence: Source confirms CVE-2026-76461 is actively exploited
  mitigation_plan:
    - priority: immediate
      action: Patch affected Cisco products to versions 15.5.5-014, 16.0.4-302, 16.5.0-780 or higher
      owner: IT Operations
      addresses: CVE-2026-76461
      evidence: Cisco security advisory (cisco-sa-esa-inj-2bLVGmhX)
---

Cisco has issued a security advisory regarding a SQL injection vulnerability identified as CVE-2026-76461, which impacts Cisco AsyncOS for Cisco Secure Email Gateway, Cisco Secure Email Gateway, and Cisco Secure Email and Web Manager. This vulnerability allows an unauthenticated, remote attacker to execute arbitrary SQL commands on the underlying database of the affected appliance, potentially leading to unauthorized data exfiltration or system compromise. Cisco reports that this vulnerability is being actively exploited in the wild, and it has been subsequently added to the CISA Known Exploited Vulnerabilities (KEV) Catalog. The flaw necessitates an immediate upgrade to the patched versions provided by the vendor to remediate the exposure.

## Impact

Successful exploitation of CVE-2026-76461 allows unauthorized attackers to interact with the backend databases of affected Cisco Secure Email appliances. Given the sensitivity of email security gateways, successful exploitation could lead to the exposure of configuration data, message metadata, or other system information. The inclusion of this CVE in the CISA KEV catalog underscores the high risk of widespread exploitation against organizations utilizing these gateway appliances in their perimeter defenses.

## Recommendation

1. Patch all affected Cisco products immediately to the recommended versions listed in the vendor advisory: Upgrade Cisco AsyncOS for Cisco Secure Email Gateway to 15.5.5-014, 16.0.4-302, 16.5.0-780 or later.
2. Upgrade Cisco Secure Email Gateway to version 15.5.5-014, 16.5.0-780 or later.
3. Upgrade Cisco Secure Email and Web Manager to 15.5.5-006, 16.5.0-429 or later.
4. Monitor web access logs on these appliances for anomalous HTTP requests containing SQL syntax (e.g., SELECT, UNION, SLEEP) targeting administrative or API endpoints.
5. Review the official Cisco security advisory (cisco-sa-esa-inj-2bLVGmhX) for further technical details and guidance.
