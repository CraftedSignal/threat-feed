---
title: Local Privilege Escalation in Red Hat Automatic Bug Reporting Tool
slug: 2026-08-abrt-priv-esc
description: The Red Hat Automatic Bug Reporting Tool (ABRT) contains a local privilege escalation vulnerability (CVE-2015-5287) that allows unauthorized users to gain elevated access via symlink attacks.
date: "2026-08-26T20:17:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:redhat:automatic_bug_reporting_tool:*:*:*:*:*:*:*:*
  - cpe:2.3:o:oracle:linux:7:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:6.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_desktop:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_hpc_node:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_server:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_workstation:7.0:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - Automatic Bug Reporting Tool
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Red Hat Automatic Bug Reporting Tool (ABRT) contains a privilege escalation vulnerability that could allow local users with certain permissions to gain privileges via a symlink attack.
    confidence_band: high
cves:
  - id: CVE-2015-5287
    cvss: 7.8
    epss: 0.03412
references:
  - https://www.cve.org/CVERecord?id=CVE-2015-5287
  - https://nvd.nist.gov/vuln/detail/CVE-2015-5287
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://github.com/abrt/abrt/commit/3c1b60cfa62d39e5fff5a53a5bc53dae189e740e
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Assess enterprise assets for presence of vulnerable ABRT versions
      owner: IT Operations
      due: 24h
      evidence: CISA BOD 26-04 compliance requirements
---

CVE-2015-5287 is a privilege escalation vulnerability within the Red Hat Automatic Bug Reporting Tool (ABRT), an open-source utility designed to collect and report diagnostic data. An attacker with local access can exploit improper file handling during the reporting process, specifically through a symlink attack targeting files with predictable names. By redirecting file operations to sensitive system files, a malicious local user may gain escalated privileges on the host system. This vulnerability has been added to the CISA Known Exploited Vulnerabilities (KEV) catalog. Given that ABRT is frequently installed on RHEL-based systems, security teams should assess current exposure, particularly on systems running older or end-of-life software versions, as indicated by CISA BOD 26-04.

## Impact

Successful exploitation allows a local user to escalate privileges beyond their current authorization level, potentially leading to full system compromise. The impact is primarily restricted to systems where the ABRT service is active and local users have sufficient permissions to initiate reporting processes. Organizations still running affected, legacy versions of RHEL or related distributions are at the highest risk.

## Recommendation

* Transition away from end-of-life versions of the Red Hat Automatic Bug Reporting Tool as advised by the vendor and CISA.
* Evaluate internet-facing assets for the presence of the vulnerable ABRT package and ensure patching or removal in accordance with CISA BOD 26-04.
* Conduct a forensics triage of assets identified as running legacy or vulnerable versions of ABRT following CISA guidance.
