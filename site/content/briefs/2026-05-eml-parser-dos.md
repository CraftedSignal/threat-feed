---
title: CVE-2026-44844 eml_parser Recursion Denial-of-Service
slug: 2026-05-eml-parser-dos
description: CVE-2026-44844 is a denial-of-service vulnerability in Microsoft's eml_parser due to recursion in nested message/rfc822 attachments, potentially causing a service outage.
date: "2026-05-28T07:24:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - vulnerability
  - eml_parser
vendors:
  - Microsoft
products:
  - eml_parser
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-44844
    epss: 0.00016
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44844
rules:
  - title: Detects CVE-2026-44844 Exploitation Attempt — Excessive Recursion in Email Processing
    description: Detects CVE-2026-44844 exploitation attempt — Monitors for excessive nesting depth during email parsing operations, potentially indicating a denial-of-service attack
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-44844 Exploitation Attempt — High CPU Usage by eml_parser
    description: Detects CVE-2026-44844 exploitation attempt — Monitors for excessive CPU usage by eml_parser processes, which may indicate a denial-of-service condition due to recursive parsing.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-44844 is a denial-of-service vulnerability affecting Microsoft's eml_parser component. The vulnerability stems from excessive recursion when processing nested message/rfc822 attachments within email messages. An attacker can exploit this vulnerability by crafting a malicious email with deeply nested attachments, causing the eml_parser to consume excessive resources and potentially leading to a denial-of-service condition. This vulnerability was disclosed in a Microsoft Security Response Center security update on May 28, 2026. Successful exploitation could disrupt email services relying on the affected eml_parser.

## Attack Chain

1. An attacker crafts a malicious email message containing multiple levels of nested message/rfc822 attachments.
2. The attacker sends the specially crafted email to a target system.
3. The email is received and processed by a mail server or email client utilizing the vulnerable eml_parser.
4. The eml_parser attempts to parse the nested attachments recursively.
5. The deep nesting causes excessive resource consumption (CPU and memory).
6. The eml_parser process becomes unresponsive or crashes due to resource exhaustion.
7. The mail server or email client experiences a denial-of-service condition, impacting email processing for other users.

## Impact

Successful exploitation of CVE-2026-44844 can lead to a denial-of-service condition, preventing users from accessing or processing email. The impact can range from temporary service disruptions to complete email server outages, depending on the severity of the resource exhaustion and the system's recovery capabilities.

## Recommendation

- Deploy the Sigma rules provided in this brief to detect potential exploitation attempts targeting CVE-2026-44844.
- Monitor email processing systems for unusual resource consumption patterns, as indicated in the rule descriptions.
- Review and adjust email processing configurations to limit recursion depth for attachment parsing.
- Consider implementing rate limiting for email processing to mitigate the impact of denial-of-service attacks.
