---
title: Multiple Vulnerabilities in IBM App Connect Enterprise
slug: 2026-09-ibm-app-connect-vulnerabilities
description: IBM App Connect Enterprise is affected by multiple vulnerabilities, including CVE-2024-45090 through CVE-2024-45094, which enable security bypass, denial-of-service, information disclosure, file manipulation, and cross-site scripting.
date: "2026-09-28T16:15:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:ibm:hardware_management_console_r10.0_firmware:10.0.245.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r10.0_firmware:10.1.3.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r9.4_firmware:89.40.83.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r9.4_firmware:89.41.25.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r9.4_firmware:89.42.18.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r9.3_firmware:89.33.45.0:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:hardware_management_console_r9.3_firmware:89.33.52.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:urbancode_deploy:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - enterprise-software
vendors:
  - IBM
products:
  - App Connect Enterprise
cves:
  - id: CVE-2024-45094
    cvss: 5.5
    epss: 0.00211
  - id: CVE-2024-45091
    cvss: 6.2
    epss: 0.00205
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3596
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all IBM App Connect Enterprise deployments.
      owner: IT Operations
      due: 24h
      evidence: Source advisory notification of multiple vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Patch IBM App Connect Enterprise to the latest version as directed by the vendor.
      owner: IT Operations
      addresses: CVE-2024-45090, CVE-2024-45091, CVE-2024-45092, CVE-2024-45093, CVE-2024-45094
      evidence: Vendor security advisory.
---

IBM has released a security advisory regarding multiple vulnerabilities affecting IBM App Connect Enterprise. The identified vulnerabilities, tracked as CVE-2024-45090, CVE-2024-45091, CVE-2024-45092, CVE-2024-45093, and CVE-2024-45094, allow unauthenticated or authenticated attackers to compromise the integrity and availability of the application. 

These flaws permit a wide range of malicious activities, including the bypassing of existing security controls, triggering denial-of-service (DoS) conditions that disrupt service availability, unauthorized information disclosure of sensitive data, arbitrary file manipulation, and the execution of cross-site scripting (XSS) attacks. Defenders should prioritize auditing instances of IBM App Connect Enterprise for these specific CVEs and ensure that security patches are applied to mitigate the risk of unauthorized access or service disruption.
