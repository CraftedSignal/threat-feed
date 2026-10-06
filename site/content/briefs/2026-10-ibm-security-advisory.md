---
title: IBM Security Advisory Covering Multiple Vulnerabilities
slug: 2026-10-ibm-security-advisory
description: IBM has released security patches addressing multiple vulnerabilities across DataStage on Cloud Pak for Data, Guardium Data Protection, and IBM i, including an incorrect permission assignment in the IBM i Network Authentication Service (CVE-2026-84414).
date: "2026-10-06T00:49:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:ibm:i:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - enterprise-software
  - informational
vendors:
  - IBM
products:
  - DataStage on Cloud Pak for Data (5.4.0.0)
  - Guardium Data Protection (12.2)
  - IBM i (7.3, 7.4, 7.5, 7.6)
cves:
  - id: CVE-2026-84414
    cvss: 7.8
    epss: 0.00093
references:
  - https://cyber.gc.ca/en/alerts-advisories/ibm-security-advisory-av26-997
  - https://www.ibm.com/support/pages/node/7288649
  - https://www.ibm.com/support/pages/node/7288040
  - https://www.ibm.com/support/pages/node/7289443
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  mitigation_plan:
    - priority: immediate
      action: Apply updates for DataStage, Guardium, and IBM i per IBM support pages
      owner: IT Operations
      addresses: CVE-2026-84414 and associated product vulnerabilities
      evidence: Source advisory directs administrators to apply necessary updates
---

IBM has issued a security advisory (AV26-997) regarding multiple vulnerabilities identified in several of its enterprise software products. The advisory highlights that DataStage on Cloud Pak for Data (version 5.4.0.0), Guardium Data Protection (version 12.2), and IBM i (versions 7.3, 7.4, 7.5, and 7.6) are impacted. Most notably, IBM i contains an incorrect permission assignment vulnerability in the Network Authentication Service, which is tracked under CVE-2026-84414. While the specific nature of the vulnerabilities in DataStage and Guardium is documented in the associated vendor bulletins, these issues generally represent potential risks to data integrity and system access control. Organizations utilizing these platforms should review the referenced IBM support pages to apply the relevant security updates and mitigate potential unauthorized access or privilege escalation risks.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized permission assignments, potential privilege escalation, or unauthorized access to protected data within the affected IBM enterprise environments. Organizations operating these versions in production environments are at risk of security posture degradation if patches are not applied.

## Recommendation

Prioritize the immediate application of security patches for the affected IBM products as documented in the vendor support bulletins. Specifically, address CVE-2026-84414 within IBM i environments to resolve the incorrect permission assignment in the Network Authentication Service. Perform an inventory check to identify all running instances of DataStage on Cloud Pak for Data version 5.4.0.0 and Guardium Data Protection version 12.2 to schedule maintenance windows for required updates. Monitor official IBM Product Security Incident Response bulletins for any further updates regarding these vulnerabilities.
