---
title: Remote Code Execution Vulnerability in Kaspersky Secure Mail Gateway
slug: 2026-09-kaspersky-smg-rce
description: A critical remote code execution vulnerability, CVE-2023-41056, in Kaspersky Secure Mail Gateway allows unauthenticated attackers to execute arbitrary code on affected appliances.
date: "2026-09-19T01:44:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kaspersky:secure_mail_gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-appliance
vendors:
  - Kaspersky
products:
  - Secure Mail Gateway (< 3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability permits an unauthenticated remote attacker to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability allows an attacker to provoke remote arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2023-41056
    cvss: 8.1
    epss: 0.02582
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1201/
  - https://support.kaspersky.com/vulnerability/list-of-advisories/12430#170926
  - https://www.cve.org/CVERecord?id=CVE-2023-41056
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kaspersky Secure Mail Gateway to version 3.1 or later.
      owner: IT Operations
      due: 24h
      evidence: Kaspersky security bulletin 12430#170926
  mitigation_plan:
    - priority: immediate
      action: Patch appliance to version 3.1.
      owner: IT Operations
      addresses: CVE-2023-41056
      evidence: Vendor advisory instructions
---

Kaspersky has released a security advisory addressing a remote code execution vulnerability, identified as CVE-2023-41056, within its Secure Mail Gateway product. The vulnerability affects all versions prior to 3.1. This flaw permits an unauthenticated remote attacker to execute arbitrary code on the underlying appliance, potentially leading to a full system compromise. Given that email gateways are internet-facing and process external traffic, this vulnerability represents a high risk for organizations using this software. Defenders should prioritize updating affected appliances to version 3.1 or later as documented in the Kaspersky security bulletin.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to gain remote code execution capabilities on the gateway. This could result in unauthorized access to internal email communications, potential interception of sensitive information, or the use of the appliance as a beachhead to pivot into the internal corporate network.

## Recommendation

* Upgrade all instances of Kaspersky Secure Mail Gateway to version 3.1 or later immediately.
* Monitor external-facing network perimeters for anomalous traffic patterns directed at the mail gateway appliance, specifically checking for unconventional payloads in SMTP or management traffic.
* Review the official Kaspersky security bulletin (12430#170926) for additional hardening steps or configuration changes recommended by the vendor.
