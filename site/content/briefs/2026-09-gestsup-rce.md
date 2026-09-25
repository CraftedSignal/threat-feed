---
title: Remote Code Execution in GestSup IMAP Connector
slug: 2026-09-gestsup-rce
description: GestSup versions before 3.2.61 are vulnerable to unauthenticated remote code execution via malicious file attachments in the IMAP connector.
date: "2026-09-25T22:55:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gestsup:gestsup:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - vulnerability
vendors:
  - GestSup
products:
  - GestSup (< 3.2.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An unauthenticated attacker can exploit this by sending emails containing PHP files, which are saved to a web-accessible directory and subsequently executed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The application fails to skip blocked file extensions... and executed when accessed.
    confidence_band: high
cves:
  - id: CVE-2026-100389
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100389
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade GestSup to 3.2.61 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies 3.2.61 as the fixed version
  mitigation_plan:
    - priority: immediate
      action: Disable PHP execution in the upload/ticket directory via web server configuration
      owner: IT Operations
      addresses: CVE-2026-100389
---

GestSup versions prior to 3.2.61 contain a critical remote code execution (RCE) vulnerability located within the basic IMAP connector's attachment handling logic. The vulnerability exists because the software fails to properly validate or filter blocked file extensions when processing incoming emails for support tickets. 

An unauthenticated attacker can exploit this flaw by sending an email containing a malicious PHP script as an attachment to a mailbox monitored by the GestSup IMAP connector. The application subsequently saves this attachment directly to a web-accessible directory, specifically the upload/ticket folder. By navigating to the URL of the uploaded file, an attacker can trigger the execution of the PHP script, gaining unauthorized code execution on the underlying server. This flaw poses a high risk to organizations relying on the IMAP integration for automated ticket creation.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code on the web server hosting GestSup. This can lead to full system compromise, data theft from the ticketing system, and potential lateral movement into the internal network environment.

## Recommendation

* Immediately upgrade GestSup to version 3.2.61 or later to implement proper file extension validation.
* Restrict access to the upload/ticket directory via web server configuration to prevent direct execution of PHP or other script files.
* Audit the upload/ticket directory for any unauthorized PHP files or anomalous scripts that may have been uploaded via the IMAP connector.
