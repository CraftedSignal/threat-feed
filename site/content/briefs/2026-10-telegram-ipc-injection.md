---
title: Telegram Desktop IPC Record-Separator Injection
slug: 2026-10-telegram-ipc-injection
description: Telegram Desktop versions prior to 7.2.9 contain an IPC record-separator injection vulnerability in the Core::Sandbox component, allowing remote attackers to exfiltrate local session data via crafted tg:// links.
date: "2026-10-07T14:37:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:telegram:telegram_desktop:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ipc
  - exfiltration
vendors:
  - Telegram
products:
  - Telegram Desktop (< 7.2.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: 'By leveraging crafted tg:// links containing unescaped semicolons, remote attackers can trigger the interpret: scheme handler.'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'Attacker can reach the interpret: scheme handler to upload local files, including tdata session keys, to an attacker channel.'
    confidence_band: high
cves:
  - id: CVE-2026-107181
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107181
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Telegram Desktop to version 7.2.9 or later.
      owner: IT Operations
      addresses: CVE-2026-107181
      evidence: Telegram Desktop before 7.2.9 contains an IPC record-separator injection vulnerability.
---

Telegram Desktop versions prior to 7.2.9 contain an IPC record-separator injection vulnerability within the Core::Sandbox component. This vulnerability is triggered when a user interacts with a specially crafted tg:// URI containing unescaped semicolons. By exploiting this flaw, an attacker can bypass IPC security boundaries to reach the interpret: scheme handler. This allows the attacker to force the application to read and upload local files, specifically targeting critical tdata session keys. If successful, this exfiltration leads to a complete account takeover, as the attacker can use the stolen session data to impersonate the victim. The attack is particularly dangerous because it relies on user-triggered URI handling, which is a common mechanism for cross-application communication in modern desktop environments.

## Impact

Successful exploitation of CVE-2026-107181 results in full account takeover for users of Telegram Desktop. By exfiltrating tdata session keys, attackers gain unauthorized access to the victim's Telegram account, enabling them to read private messages, impersonate the user, and potentially propagate further malicious links or malware through the victim's existing contact list.

## Recommendation

Update all Telegram Desktop installations to version 7.2.9 or later immediately. Ensure that browser and OS-level URI handlers are monitored for unexpected or repetitive attempts to trigger tg:// links, particularly those containing encoded characters or unusual parameters.
