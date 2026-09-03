---
title: Path Traversal Vulnerability in rubyzip
slug: 2026-09-rubyzip-path-traversal
description: rubyzip versions before 3.4.0 are vulnerable to path traversal within the Zip::Entry#extract method, allowing attackers to write files outside the intended directory via malicious archive entries.
date: "2026-09-03T19:23:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rubyzip_project:rubyzip:*:*:*:*:*:ruby:*:*
vendors:
  - rubyzip
products:
  - rubyzip (< 3.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The vulnerability is triggered by extracting malicious archive entries, often delivered via user-supplied uploads or attachments.
    confidence_band: med
cves:
  - id: CVE-2026-85396
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85396
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade rubyzip to version 3.4.0 or later in all software dependencies
      owner: Application Security
      addresses: CVE-2026-85396
      evidence: Source NVD advisory recommends version 3.4.0 for remediation
---

rubyzip versions prior to 3.4.0 contain a critical path traversal vulnerability in the Zip::Entry#extract method. The library fails to perform robust validation when checking destination paths, specifically failing to account for cases where prefix comparison is performed without trailing directory separators. An attacker can create a specially crafted ZIP archive containing entries with path traversal sequences such as ../ in the filename. When an application using an affected version of rubyzip extracts such an archive, the library may incorrectly resolve the target path to a location outside the designated extraction directory. By targeting sensitive directories, an attacker could potentially overwrite configuration files, inject scripts into startup folders, or gain arbitrary code execution depending on the application's environment and permissions.

## Impact

Successful exploitation allows for unauthorized file writes on the host system. Depending on the target application's use case, this can lead to remote code execution, persistence, or configuration tampering. The vulnerability affects any application or service utilizing the rubyzip library for processing untrusted archive uploads.

## Recommendation

- Update the rubyzip dependency to version 3.4.0 or later across all projects.
- Audit applications utilizing rubyzip for file extraction to identify if archives are processed from untrusted user inputs.
- Implement file path validation at the application level to ensure extracted file paths reside within the expected destination directory.
