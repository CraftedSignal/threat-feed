---
brief_id: brief-2026-11-08-unrealircd-rce
event_id: brief-2026-11-08-unrealircd-rce
revision: 1
activity_at: "2026-11-08T08:31:42Z"
title: 'UnrealIRCd: Command injection in labeled-response module (CVE-2026-114713)'
slug: 2026-11-unrealircd-rce
description: A command injection vulnerability in the UnrealIRCd labeled-response module allows unauthenticated attackers on linked networks to execute server-to-server commands with elevated authority via unescaped IRCv3 label tags.
date: "2026-11-08T08:31:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability and fixed version provided.
cpes:
  - cpe:2.3:a:unrealircd:unrealircd:6.0.0:*:*:*:*:*:*:*
vendors:
  - UnrealIRCd
products:
  - UnrealIRCd (6.0.0 - 6.2.7.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The labeled-response module... allows any user on a network with two or more linked servers to inject server-to-server commands that are executed with server authority.
    confidence_band: high
cves:
  - id: CVE-2026-114713
    cvss: 8.6
    kev_status: "false"
references:
  - https://www.unrealircd.org/index/news
  - https://forums.unrealircd.org/viewtopic.php?t=9487
  - https://sploitus.com/exploit?id=CVE-2026-114713
  - https://sploitus.com/exploit?id=CVE-2026-114713&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all UnrealIRCd instances to version 6.2.7.1.
      owner: IT Operations
      due: 24h
      evidence: UnrealIRCd 6.0.0 before 6.2.7.1 does not escape the IRCv3 label message tag.
  hunt_leads:
    - lead: Monitor S2S traffic logs for malformed IRCv3 label tags containing control characters or command injection vectors (e.g., semicolons, pipe characters, or unexpected line breaks).
      technique_id: T1059
      data_needed:
        - Network traffic logs / IRC server logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unescaped IRCv3 "label" tags... allow command injection.
  mitigation_plan:
    - priority: immediate
      action: Upgrade UnrealIRCd to 6.2.7.1.
      owner: IT Operations
      addresses: CVE-2026-114713
      evidence: UnrealIRCd 6.0.0 before 6.2.7.1 is affected.
---

CVE-2026-114713 is a command injection vulnerability affecting the labeled-response module in UnrealIRCd versions 6.0.0 through 6.2.7.0. The vulnerability occurs because the application fails to properly escape IRCv3 "label" tags when echoing them into server replies. On networks with two or more linked servers, an attacker can leverage this flaw to inject arbitrary server-to-server commands that execute with the authority of the server. This vulnerability carries a CVSS score of 8.6.

## Impact

Successful exploitation allows for the execution of unauthorized server-to-server commands, potentially leading to full network compromise, unauthorized modifications to IRC services, or service disruption, as commands are processed with server-level privileges.

## Recommendation

* Upgrade all UnrealIRCd instances to version 6.2.7.1 or later immediately to address the insecure handling of IRCv3 tags.
* Audit server-to-server (S2S) traffic logs for unusual command patterns or syntax deviations in label-related messages.
* For environments unable to patch immediately, isolate linked IRC servers to restrict the potential blast radius of server-to-server command injection.
