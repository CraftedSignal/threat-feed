---
title: Path Traversal Vulnerability in RosarioSIS
slug: 2026-09-rosariosis-path-traversal
description: Authenticated users can exploit improper filename validation in RosarioSIS versions prior to 12.9 to perform unauthorized file deletion via directory traversal.
date: "2026-09-17T17:59:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rosariosis:rosariosis:*:*:*:*:*:*:*:*
vendors:
  - RosarioSIS
products:
  - RosarioSIS (< 12.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can use parent-directory sequences to escape upload directories and delete CSS, XML, JSON resources and other users' documents throughout the installation.
    confidence_band: high
cves:
  - id: CVE-2026-93014
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93014
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade RosarioSIS to 12.9 or later
      owner: IT Operations
      due: 24h
      evidence: Source states RosarioSIS versions before 12.9 fail to validate the filename request parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade RosarioSIS to 12.9 or later
      owner: IT Operations
      addresses: CVE-2026-93014
      evidence: NVD vulnerability disclosure specifies versions prior to 12.9 are affected.
---

RosarioSIS versions prior to 12.9 contain a path traversal vulnerability in the Users and Students modules. This issue arises due to insufficient validation of the 'filename' request parameter, which is used during file handling operations. An authenticated attacker can manipulate this parameter by injecting directory traversal sequences (e.g., ../) to escape the intended upload or application directories. Successful exploitation allows the attacker to delete arbitrary files across the application installation, including system-critical resources like CSS, XML, and JSON configuration files, or sensitive documents belonging to other users. This vulnerability represents a significant risk to application integrity and data confidentiality, as it enables destructive actions against the underlying file system within the scope of the web application user.

## Impact

Successful exploitation results in the unauthorized deletion of arbitrary files within the web root and potentially the wider application directory, leading to service disruption, loss of configuration, or data loss. The vulnerability affects the confidentiality and availability of the RosarioSIS installation.

## Recommendation

Prioritized actions for security and IT operations teams:

- Upgrade RosarioSIS to version 12.9 or later immediately to incorporate the required filename validation patches.
- Audit access logs for web requests containing directory traversal sequences (e.g., "..%2f" or "../") targeting the Users or Students modules.
- Implement restrictive file system permissions to ensure the web server user only has write access to designated upload directories, preventing unauthorized deletion of system files.
