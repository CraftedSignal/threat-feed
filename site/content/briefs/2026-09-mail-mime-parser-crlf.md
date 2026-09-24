---
title: CRLF Header Injection Vulnerability in mail-mime-parser
slug: 2026-09-mail-mime-parser-crlf
description: The zbateson/mail-mime-parser library is vulnerable to CRLF header injection (CVE-2026-61815), allowing attackers to inject arbitrary email headers such as Bcc for silent data exfiltration.
date: "2026-09-24T20:04:50Z"
lastmod: "2026-09-24T20:04:59Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:zbateson:mail_mime_parser:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - php
  - mail-mime-parser
vendors:
  - zbateson
products:
  - mail-mime-parser (v3.0.6, v4.0.2)
  - mail-mime-parser (2.0.0-3.0.5, 4.0.0-4.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The untrusted filename can come directly from parsed inbound mail, so no local construction is required
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: a forged Bcc that silently exfiltrates a copy of the outgoing message
    confidence_band: high
cves:
  - id: CVE-2026-61815
    cvss: 7.2
references:
  - https://github.com/advisories/GHSA-36h5-qg4p-q2qf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61815
  - https://github.com/advisories/GHSA-f6v3-2qmr-vfjx
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-61816
iocs:
  - type: email
    value: attacker@evil.test
ioc_counts:
  email: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade mail-mime-parser to 3.0.6 or 4.0.2
      owner: IT Operations
      due: 48h
      evidence: Patches for CVE-2026-61815 are available in 3.0.6 and 4.0.2
  mitigation_plan:
    - priority: immediate
      action: Implement CRLF sanitization on filename parameters in code
      owner: Application Development
      addresses: CVE-2026-61815
      evidence: Source provides preg_replace workaround
updates:
  - at: "2026-09-24T20:04:59Z"
    level: L1
    summary: added coverage for mail-mime-parser (2.0.0-3.0.5, 4.0.0-4.0.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-f6v3-2qmr-vfjx
---

The zbateson/mail-mime-parser library (versions < 3.0.6 and 4.0.0 through 4.0.1) contains a CRLF header injection vulnerability, identified as CVE-2026-61815. The flaw exists because the library fails to properly sanitize carriage-return (CR) and line-feed (LF) characters from attachment filenames during both the parsing of inbound MIME messages and the construction of outbound messages. 

An attacker can exploit this by crafting a malicious attachment filename containing encoded CRLF characters. When an application parses a message containing such a filename and subsequently re-attaches or re-forwards the file, the library inadvertently serializes the CRLF characters into the email headers. This allows the attacker to inject arbitrary email headers, such as 'Bcc', enabling the silent exfiltration of email content to an attacker-controlled address. This vulnerability affects any application logic that retrieves a filename from a parsed message and uses it to construct a new MIME part.

## Impact

Successful exploitation allows for the silent exfiltration of sensitive email communications via unauthorized 'Bcc' header injection. Any enterprise application that automatically processes, forwards, or re-attaches files from inbound emails using the vulnerable library version is at risk.

## Recommendation

Prioritized, concrete actions:
- Upgrade the zbateson/mail-mime-parser library to version 3.0.6 or 4.0.2 immediately.
- If immediate patching is not feasible, implement a strict sanitization routine to strip CR and LF characters from any filename retrieved via `getFilename()` before using it in any outbound email construction, such as: `preg_replace('/[\r\n]+/', ' ', $filename)`.
- Conduct a code review of downstream applications using mail-mime-parser to identify instances where filenames parsed from inbound messages are reused in outgoing mail construction.
