---
title: Multiple Vulnerabilities in Oracle Hyperion
slug: 2026-09-oracle-hyperion-vulnerabilities
description: Oracle Hyperion is affected by multiple security vulnerabilities (CVE-2024-21054, CVE-2024-21055) that allow remote attackers to compromise system confidentiality, integrity, and availability.
date: "2026-09-16T13:08:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:oracle:mysql_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*
  - cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:oncommand_workflow_automation:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:bluexp:-:*:*:*:*:*:*:*
tags:
  - vulnerability
  - enterprise-application
vendors:
  - Oracle
products:
  - Hyperion
cves:
  - id: CVE-2024-21054
    cvss: 4.9
    epss: 0.00962
  - id: CVE-2024-21055
    cvss: 4.9
    epss: 0.00887
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Apply the latest security patches for Oracle Hyperion to remediate CVE-2024-21054 and CVE-2024-21055.
      owner: IT Operations
      addresses: CVE-2024-21054, CVE-2024-21055
      evidence: Source advisory WID-SEC-2026-3397
---

Oracle Hyperion has been identified as containing multiple security vulnerabilities, tracked as CVE-2024-21054 and CVE-2024-21055. These flaws allow remote, anonymous, or authenticated attackers to perform unauthorized actions against affected systems. By exploiting these vulnerabilities, an adversary may gain the ability to bypass access controls, execute arbitrary code, or access sensitive data, resulting in a full compromise of the application's confidentiality, integrity, and availability. Organizations using Oracle Hyperion should evaluate their exposure and apply the necessary security patches or mitigations provided by the vendor to remediate these risks.

## Impact

Successful exploitation of these vulnerabilities allows for a total compromise of the Oracle Hyperion application. This includes potential unauthorized data access, manipulation of enterprise performance management data, and complete system takeover. Organizations in sectors relying on Hyperion for financial planning and analysis are at significant risk of operational disruption and data exfiltration if left unpatched.

## Recommendation

Prioritize the identification of all Oracle Hyperion instances within the production environment and apply the security updates provided by Oracle to address CVE-2024-21054 and CVE-2024-21055. Monitor web application access logs for unusual traffic patterns originating from external sources or unauthorized authenticated sessions.
