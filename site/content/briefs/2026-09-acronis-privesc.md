---
title: Privilege Escalation Vulnerability in Acronis Backup for cPanel and Plesk
slug: 2026-09-acronis-privesc
description: Acronis Backup for cPanel and WHM and the extension for Plesk contain an incorrect default permissions vulnerability (CVE-2026-87886) that enables privilege escalation.
date: "2026-09-17T00:59:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acronis:backup:*:*:*:*:*:cpanel:*:*
  - cpe:2.3:a:acronis:backup:*:*:*:*:*:plesk:*:*
tags:
  - vulnerability
  - privilege-escalation
  - server-security
vendors:
  - Acronis
products:
  - Backup (for cPanel and WHM)
  - Backup (extension for Plesk)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Acronis Backup plugin for cPanel & WHM and extension for Plesk contains an incorrect default permissions vulnerability that could allow for privilege escalation.
    confidence_band: high
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-87886
  - https://security-advisory.acronis.com/advisories/SEC-10986
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87886
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Acronis Backup plugins to the version specified in the vendor advisory SEC-10986.
      owner: IT Operations
      due: "2026-09-19"
      evidence: CISA-KEV mandated due date of 2026-09-19 for CVE-2026-87886.
  mitigation_plan:
    - priority: immediate
      action: Review server permissions for Acronis plugin directories for deviations from principle of least privilege.
      owner: Security Operations
      addresses: CVE-2026-87886
      evidence: Source describes incorrect default permissions as the primary vulnerability mechanism.
---

Acronis Backup for cPanel and WHM, as well as the Acronis extension for Plesk, are affected by an incorrect default permissions vulnerability identified as CVE-2026-87886. This flaw exists within the plugin's file or directory permission structure, which is improperly configured during installation or runtime. An attacker with limited access to the server environment where these panels reside could leverage these insecure permissions to perform unauthorized actions, effectively escalating their privileges to the context of the backup service or the panel itself. Given the elevated nature of these administrative interfaces, this vulnerability poses a significant risk to the integrity and confidentiality of backed-up data and the underlying server infrastructure. Defenders are required to prioritize patching in accordance with CISA Binding Operational Directive (BOD) 26-04.

## Impact

Successful exploitation of CVE-2026-87886 allows local unprivileged users to escalate privileges, potentially leading to unauthorized data access, modification of backup configurations, or full control over the cPanel or Plesk management interfaces. This affects organizations utilizing Acronis Backup plugins in shared hosting or enterprise management environments. Impacted systems are subject to strict remediation timelines under CISA BOD 26-04 to prevent potential lateral movement and data exfiltration.

## Recommendation

Prioritize the immediate application of vendor-supplied patches for Acronis Backup plugins in accordance with CISA BOD 26-04. Verify the integrity of file permissions for the Acronis plugin directories post-patching. If patches are unavailable, evaluate the business necessity of the plugin and consider disabling the extension until remediation is confirmed. Consult the vendor security advisory at https://security-advisory.acronis.com/advisories/SEC-10986 for specific version requirements.
