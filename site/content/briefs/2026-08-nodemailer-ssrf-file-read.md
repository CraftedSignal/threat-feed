---
title: Nodemailer SSRF and Arbitrary File Read Vulnerability
slug: 2026-08-nodemailer-ssrf-file-read
description: Nodemailer versions before 9.0.1 fail to enforce security flags when processing message-level raw options, allowing authenticated attackers to perform SSRF and read arbitrary files.
date: "2026-08-31T11:17:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nodemailer:nodemailer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - file-access
products:
  - nodemailer (< 9.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated attacker can leverage this oversight to supply malicious file paths or URLs, enabling arbitrary file read or server-side request forgery (SSRF).
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The resulting data or response is then exfiltrated to an attacker-controlled recipient via the outgoing email.
    confidence_band: high
cves:
  - id: CVE-2026-82659
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82659
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade nodemailer to 9.0.1 or later.
      owner: IT Operations
      addresses: CVE-2026-82659
      evidence: Nodemailer versions prior to 9.0.1 fail to properly apply 'disableFileAccess' and 'disableUrlAccess' security flags.
---

Nodemailer versions prior to 9.0.1 contain a security oversight where the 'disableFileAccess' and 'disableUrlAccess' flags are not properly applied when processing message-level 'raw' options. This flaw allows an authenticated attacker to provide malicious path or href properties within the email structure. By exploiting this, an attacker can coerce the server into performing server-side request forgery (SSRF) to interact with internal resources or to read arbitrary files from the filesystem. The contents of these files or the response from the internal requests are then exfiltrated to an attacker-controlled recipient via the outgoing email message. This vulnerability poses a significant risk to applications using Nodemailer to process user-supplied email content or templates, as it bypasses intended security sandbox restrictions.

## Impact

Successful exploitation allows authenticated users to exfiltrate sensitive internal configuration files, credentials, or metadata via email. It also facilitates SSRF, enabling attackers to probe internal network services and sensitive APIs that are not exposed to the public internet, potentially leading to further compromise of the internal environment.

## Recommendation

Update Nodemailer to version 9.0.1 or later immediately to ensure that 'disableFileAccess' and 'disableUrlAccess' flags are correctly enforced during message processing.
