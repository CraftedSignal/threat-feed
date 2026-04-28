---
title: FreeScout Privilege Escalation via Email Address Reassignment (CVE-2026-40589)
slug: 2026-04-freescout-privesc
description: FreeScout versions before 1.8.214 are vulnerable to privilege escalation, allowing a low-privileged agent to reassign email addresses from hidden customers to visible customers, leading to information disclosure and unauthorized access to conversations.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - privilege-escalation
  - cve-2026-40589
  - freescout
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40589
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40589
  - https://github.com/freescout-help-desk/freescout/commit/2e2fe37111d92ac665b9ad8806eac94a1a3e502c
  - https://github.com/freescout-help-desk/freescout/releases/tag/1.8.214
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-mv55-3mgv-fxwr
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: FreeScout Hidden Customer Data Disclosure
    description: Detects potential attempts to exploit CVE-2026-40589 by monitoring web server logs for requests that may lead to hidden customer data disclosure in FreeScout.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: FreeScout Suspicious Email Reassignment
    description: Detects suspicious email reassignment attempts in FreeScout by monitoring for specific patterns in web server logs.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout is a self-hosted help desk and shared mailbox system. A critical vulnerability, identified as CVE-2026-40589, exists in versions prior to 1.8.214. This flaw allows a low-privileged agent to escalate their privileges by manipulating customer records. Specifically, an agent can edit a visible customer's profile and add an email address that is already associated with a hidden customer in a different mailbox. This results in the disclosure of the hidden customer's name and profile URL within the application's success flash message. Additionally, the vulnerable server reassigns the hidden customer's email address to the visible customer and rebinds all conversations from the hidden mailbox associated with that email address to the visible customer. The vulnerability was patched in version 1.8.214. This poses a significant risk to organizations using affected versions of FreeScout, as it can lead to unauthorized access to sensitive customer data and communication.

## Attack Chain

1. A low-privileged agent logs into the FreeScout instance.
2. The agent selects a visible customer within their accessible mailbox.
3. The agent attempts to edit the visible customer's profile.
4. The agent adds an email address to the visible customer's profile that is already associated with a hidden customer in another mailbox, which the agent would normally not have access to.
5. The server validates the request and, due to the vulnerability, allows the reassignment of the email address.
6. The server discloses the hidden customer's name and profile URL in the success flash message displayed to the agent.
7. The server reassigns the hidden customer's email address to the visible customer in the database.
8. All conversations previously associated with the hidden customer's email address are now accessible to the agent through the visible customer's profile, leading to unauthorized access of customer conversations.

## Impact

Successful exploitation of CVE-2026-40589 can lead to a significant breach of confidentiality and integrity within a FreeScout instance. A low-privileged agent can gain unauthorized access to sensitive customer data, including names, profile URLs, and entire conversation histories. This can result in the compromise of customer privacy, potential regulatory violations, and damage to the organization's reputation. The number of potential victims is directly proportional to the number of customers and mailboxes within the affected FreeScout instance.

## Recommendation

*   Upgrade FreeScout instances to version 1.8.214 or later to remediate CVE-2026-40589 as mentioned in the overview.
*   Deploy the Sigma rule "FreeScout Hidden Customer Data Disclosure" to detect attempts to exploit this vulnerability in web server logs.
*   Monitor FreeScout application logs for unusual activity related to customer profile modifications.
*   Implement strict access control policies within FreeScout to minimize the potential impact of compromised agent accounts.
