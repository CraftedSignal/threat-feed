---
title: FreeScout Unauthorized Attachment Deletion Vulnerability (CVE-2026-41192)
slug: 2024-01-freescout-attachment-deletion
description: FreeScout versions prior to 1.8.215 are vulnerable to unauthorized attachment deletion, allowing a malicious mailbox peer to delete attachments by replaying encrypted attachment IDs in the `save_draft` flow.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - freescout
  - attachment-deletion
  - cve-2026-41192
vendors:
  - FreeScout
products:
  - FreeScout
cves:
  - id: CVE-2026-41192
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41192
rules:
  - title: Detect FreeScout Attachment Deletion Attempt via Save Draft
    description: Detects suspicious save_draft requests potentially exploiting CVE-2026-41192 by looking for a high number of attachment IDs in the request.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout Attachment Deletion - Attachment::deleteByIds call
    description: Detects potential attachment deletion attempts by monitoring FreeScout application logs for calls to the Attachment::deleteByIds function.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is susceptible to an unauthorized attachment deletion vulnerability in versions prior to 1.8.215. This flaw stems from the application's trust in client-supplied encrypted attachment IDs during reply and draft processes. An attacker with access to a mailbox conversation can exploit this by obtaining encrypted attachment IDs and replaying them through the `save_draft` functionality. The lack of proper validation allows the attacker to trigger the `Attachment::deleteByIds()` function, leading to the deletion of the original attachment row and file. This vulnerability was addressed in FreeScout version 1.8.215. Exploitation can result in data loss and disruption of service for affected FreeScout users.

## Attack Chain

1.  Attacker gains access to a FreeScout mailbox with visible conversations containing attachments.
2.  Attacker inspects the HTML source or API responses of a conversation to obtain encrypted attachment IDs. These IDs are associated with legitimate attachments within the conversation.
3.  The attacker crafts a malicious `save_draft` request, including the replayed encrypted attachment IDs in the `attachments_all[]` parameter.
4.  The attacker omits these replayed IDs from any retained attachment lists within the `save_draft` request.
5.  FreeScout processes the `save_draft` request and decrypts the attachment IDs present in `attachments_all[]` but absent from the retained lists.
6.  The decrypted IDs are passed to the `Attachment::deleteByIds()` function without proper validation.
7.  `Attachment::deleteByIds()` executes, deleting the original attachment row and the corresponding file from the FreeScout server.
8.  The victim user finds that the attachment has been deleted from the conversation.

## Impact

Successful exploitation of this vulnerability (CVE-2026-41192) allows an attacker to delete attachments from FreeScout conversations without proper authorization. The number of potential victims depends on the number of FreeScout installations and the number of users with access to shared mailboxes. This can lead to data loss, disruption of business processes that rely on those attachments, and a potential loss of trust in the help desk system. The CVSS v3.1 base score for this vulnerability is 7.1, indicating a high severity.

## Recommendation

*   Upgrade FreeScout installations to version 1.8.215 or later to patch CVE-2026-41192.
*   Implement web application firewall (WAF) rules to monitor and block suspicious `save_draft` requests containing potentially replayed attachment IDs (cs-uri-query, cs-method from webserver logs).
*   Monitor FreeScout application logs for calls to `Attachment::deleteByIds()` originating from unusual IP addresses or user agents (application logs).
*   Deploy the provided Sigma rule to detect suspicious patterns in web server logs indicative of exploitation attempts.
