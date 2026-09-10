---
title: Path Traversal Vulnerability in IBM DataStage
slug: 2026-09-ibm-datastage-path-traversal
description: IBM DataStage on Cloud Pak for Data 5.4.0.0 is vulnerable to path traversal during archive extraction, allowing an authenticated remote attacker to create arbitrary files on the host system.
date: "2026-09-10T23:09:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:datastage:5.4.0.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - cloud-security
vendors:
  - IBM
products:
  - DataStage (5.4.0.0)
  - Cloud Pak for Data (5.4.0.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The ability to create arbitrary files during extraction allows for the placement of malicious scripts to achieve persistence.
    confidence_band: med
cves:
  - id: CVE-2026-80424
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80424
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Patch IBM DataStage and Cloud Pak for Data 5.4.0.0 per IBM vendor guidance for CVE-2026-80424
      owner: IT Operations
      addresses: CVE-2026-80424
      evidence: NVD advisory indicates vulnerability in version 5.4.0.0
---

IBM DataStage, a component of Cloud Pak for Data version 5.4.0.0, contains a critical path traversal vulnerability (CVE-2026-80424). This vulnerability arises during the processing and extraction of archive files. A remote, authenticated attacker can exploit this flaw by crafting malicious archive content that includes path traversal sequences, such as dot-dot-slash (../). If successful, the attacker can force the application to write files to arbitrary locations outside of the intended directory. This allows for the overwrite of critical system configuration files or the placement of malicious scripts, potentially leading to unauthorized system modifications, privilege escalation, or remote code execution within the environment.

## Impact

Successful exploitation allows an authenticated attacker to achieve arbitrary file write capabilities on the server hosting the IBM DataStage instance. Given the high CVSS score of 9.1, this flaw presents a significant risk for environments where DataStage manages critical data pipelines. If exploited, an attacker could compromise the integrity of the DataStage application, gain persistence, or facilitate lateral movement by deploying backdoors.

## Recommendation

Prioritize the identification of IBM DataStage instances running on Cloud Pak for Data 5.4.0.0. Consult the official IBM PSIRT advisory for the availability of security patches and apply them immediately to mitigate CVE-2026-80424. Conduct a review of application logs for suspicious archive upload patterns or unauthorized file system write events associated with the DataStage service user.
