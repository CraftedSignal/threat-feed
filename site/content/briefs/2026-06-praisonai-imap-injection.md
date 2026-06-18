---
title: 'PraisonAI: IMAP Command Injection via Unsanitized Email Search Parameters'
slug: 2026-06-praisonai-imap-injection
description: A command injection vulnerability (CVE-NONE) exists in PraisonAI's `praisonaiagents` package (versions <= 1.6.48) where unsanitized LLM-controlled parameters are directly interpolated into IMAP SEARCH commands, allowing attackers to craft malicious prompts to inject arbitrary IMAP commands, leading to unauthorized email exfiltration, deletion, or denial-of-service when email tools are configured.
date: "2026-06-18T15:08:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - llm-agent
  - imap
  - email
  - data-exfiltration
vendors:
  - PraisonAI
products:
  - praisonaiagents (<= 1.6.48)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: ""
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://github.com/advisories/GHSA-c969-5x3p-vq3v
rules:
  - title: Detect PraisonAI IMAP Injection - Session Termination Attempt
    description: Detects attempts to inject the IMAP LOGOUT command within a SEARCH operation, indicating a PraisonAI praisonaiagents vulnerability exploitation attempt to terminate the IMAP session.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1531
    data_sources:
      - application
      - imap_server
  - title: Detect PraisonAI IMAP Injection - Exfiltration or Lateral Search
    description: Detects attempts to inject IMAP commands like 'SEARCH RETURN (MIN) ALL' or 'SELECT' within a SEARCH operation, indicating a PraisonAI praisonaiagents vulnerability exploitation for data exfiltration or lateral mailbox access.
    platform: sigma
    severity: high
    tactics:
      - collection
      - execution
    techniques:
      - T1059
      - T1114.001
    data_sources:
      - application
      - imap_server
  - title: Detect PraisonAI IMAP Injection - Destructive Action Attempt
    description: Detects attempts to inject destructive IMAP commands like 'DELETE' or 'EXPUNGE' within a SEARCH operation, indicating a PraisonAI praisonaiagents vulnerability exploitation for email deletion.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1485
    data_sources:
      - application
      - imap_server
rules_count: 3
---

A critical command injection vulnerability has been identified in the `praisonaiagents` package, affecting versions up to and including 1.6.48, developed by PraisonAI. This flaw stems from the improper sanitization of LLM-controlled parameters (such as `from_addr`, `subject`, `query`, `search_id`, and `message_id`) when constructing IMAP SEARCH commands. Attackers can leverage this by crafting malicious prompts that, when processed by an LLM agent configured with email tools, cause the agent to execute arbitrary IMAP commands on the backend mail server. This vulnerability, actively reported in June 2026, poses a significant risk to organizations using PraisonAI agents with email integration, potentially leading to sensitive data exfiltration, permanent email deletion, or denial-of-service by terminating IMAP sessions.

## Attack Chain

1.  An attacker crafts a malicious prompt containing an IMAP command injection payload, such as a double-quote followed by an IMAP command (e.g., `" LOGOUT`).
2.  An LLM agent, configured with `EMAIL_ADDRESS` and `EMAIL_PASSWORD` environment variables, processes the crafted prompt as part of its normal operation.
3.  The LLM agent calls an internal `praisonaiagents` tool function (e.g., `search_emails`, `reply_email`, or `archive_email`) passing the malicious input as a parameter (e.g., `from_addr`, `subject`, `query`, `search_id`).
4.  The `praisonaiagents` tool function dynamically constructs an IMAP `SEARCH` command by directly interpolating the unsanitized parameter into an f-string, allowing the attacker's double-quote to prematurely close the legitimate quoted string.
5.  The constructed IMAP command string, now containing an injected IMAP command (e.g., `LOGOUT`, `SELECT INBOX`, `FETCH 1:* (BODY[])`, `DELETE 1:*`, `EXPUNGE`), is sent by the `praisonaiagents` process to the configured IMAP server.
6.  The IMAP server receives the crafted command string, parses it, and executes both the legitimate `SEARCH` portion (if any) and the injected IMAP command.
7.  The injected IMAP command performs an unauthorized action on the IMAP server, such as terminating the IMAP session, switching to another mailbox, fetching email contents, modifying email flags, or deleting messages.
8.  The attacker achieves their objective, which could include exfiltrating sensitive email data, causing denial-of-service, or permanently deleting emails from the compromised mailbox.

## Impact

Successful exploitation of this vulnerability grants attackers significant control over the configured IMAP mailbox. Attackers can terminate IMAP connections, causing a denial-of-service against the agent's email capabilities. More critically, arbitrary IMAP commands can be injected, allowing the attacker to enumerate mailboxes (LIST), switch to different folders (SELECT), fetch the contents of any email (FETCH), modify email flags (STORE), move emails (COPY/MOVE), or permanently delete emails (DELETE/EXPUNGE). This leads to unauthorized email data exfiltration from potentially all accessible mailboxes, or catastrophic data loss through permanent deletion of email archives. The attack specifically targets email-capable agents deployed with the documented `EMAIL_ADDRESS` and `EMAIL_PASSWORD` environment variables, indicating a direct threat to sensitive communications.

## Recommendation

*   Immediately update the `praisonaiagents` package to a version greater than 1.6.48 (when available) or apply the recommended remediation of properly escaping double-quote characters or using IMAP literal syntax for all user-controlled parameters (`from_addr`, `subject`, `query`, `search_id`, `message_id`).
*   Monitor IMAP server logs for suspicious commands, specifically looking for unexpected IMAP keywords (e.g., `LOGOUT`, `SELECT`, `FETCH`, `DELETE`, `EXPUNGE`) embedded within `SEARCH` criteria, as outlined in the Sigma rules above.
*   Ensure IMAP server logging is enabled and captures full commands and arguments, which is essential to activate the Sigma rules in this brief.
*   Restrict the permissions of the IMAP account used by `praisonaiagents` to the bare minimum necessary for its operations (e.g., read-only access to specific folders).
