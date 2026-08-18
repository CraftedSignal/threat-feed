---
title: Nodemailer MailComposer Security Bypass Vulnerability
slug: 2026-08-nodemailer-bypass
description: Nodemailer version 9.0.0 and earlier fails to enforce security flags when using the raw message option, allowing attackers to bypass file and URL access restrictions for arbitrary file read or SSRF.
date: "2026-08-18T14:30:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - ssrf
  - file-read
  - security-bypass
vendors:
  - Nodemailer
products:
  - Nodemailer (<= 9.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The availability of a working exploit significantly elevates the risk for unpatched systems.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: MailComposer.compile() builds the raw message/rfc822 node without threading the disableFileAccess... flags, so raw:{path}... reads files.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: MailComposer.compile() builds the raw message/rfc822 node without threading the disableUrlAccess... flags, so raw:{href} fetches URLs anyway.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52654
  - https://github.com/nodemailer/nodemailer
  - https://github.com/Pig-Tail/security-research/tree/master/GHSA-p6gq-j5cr-w38f-nodemailer
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update Nodemailer dependency to 9.0.1 or later
      owner: IT Operations
      due: 48h
      evidence: Nodemailer 9.0.0 vulnerable; fixed in 9.0.1
---

Nodemailer versions 9.0.0 and earlier contain a security bypass vulnerability in the MailComposer component. The vulnerability exists because the library fails to thread the 'disableFileAccess' and 'disableUrlAccess' configuration flags when constructing the root node of a message using the 'raw' option. While Nodemailer correctly enforces these security restrictions for standard attachments and alternative nodes, the omission of these flags in the 'raw' node creation logic allows untrusted inputs to circumvent security policies. 

This issue is tracked under GHSA-p6gq-j5cr-w38f. Attackers can leverage this bypass to perform arbitrary local file reads or Server-Side Request Forgery (SSRF) against internal or external resources. Applications that rely on these flags to sanitize user-provided message data are directly impacted, as the bypass permits the processing of malicious 'path' or 'href' parameters that should otherwise be blocked. This vulnerability was confirmed in version 9.0.0 and fixed in 9.0.1.

## Impact

The impact of this vulnerability includes potential unauthorized access to sensitive local system files and the ability to conduct SSRF attacks. If an application processes user-supplied input to generate emails via Nodemailer, an attacker could read internal configuration files, credentials, or make unauthorized requests to internal services that are not reachable from the public internet. The scope of impact is dependent on the application context and the privileges of the service account running the Node.js application.

## Recommendation

- Update the Nodemailer library to version 9.0.1 or later to apply the necessary security flag enforcement.
- Audit existing application code to ensure that user-supplied input is validated before being passed into the MailComposer 'raw' configuration, even after updating the library.
- Review internal application logs for unexpected file access patterns or connection attempts originating from the application server to sensitive internal endpoints if suspicious behavior is detected.
