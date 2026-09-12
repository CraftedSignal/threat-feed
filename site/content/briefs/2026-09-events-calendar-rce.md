---
title: Remote Code Execution in The Events Calendar WordPress Plugin
slug: 2026-09-events-calendar-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-78006) exists in The Events Calendar plugin for WordPress due to insecure deserialization in the is_safe_widget_instance function.
date: "2026-09-12T09:18:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:theeventscalendar:the_events_calendar:*:*:*:*:*:wordpress:*:*
vendors:
  - The Events Calendar
products:
  - The Events Calendar (<= 6.17.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is exploitable without authentication or approval because the plugin's V2 single-event template runs do_blocks() over buffered comment HTML.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-78006
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78006
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade The Events Calendar plugin to version > 6.17.4
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78006 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Disable comments on all event pages
      owner: IT Operations
      addresses: CVE-2026-78006
      evidence: Exploit requires comments to be enabled and visible on events
---

The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution (CVE-2026-78006) in all versions up to and including 6.17.4. The vulnerability stems from insufficient protection within the `is_safe_widget_instance` function, which can be bypassed because PHP executes magic methods during pre-parsing. When combined with `enable_rendering_widget_copied()`, an attacker can forge a valid `wp_hash` integrity attribute prior to reaching an `unserialize()` call. 

The flaw is reachable by unauthenticated attackers because the plugin's V2 single-event template executes `do_blocks()` on buffered comment HTML. WordPress provides a moderation-hash URL that allows an unauthenticated user to view their own pending comment immediately. An attacker can leverage this to deliver malicious block markup to the vulnerable code path before any administrative moderation occurs. This attack requires the target WordPress instance to have comments enabled and visible on event pages. Successful exploitation allows for unauthenticated code execution on the underlying web server.

## Attack Chain

1. Attacker identifies a WordPress instance running a vulnerable version of The Events Calendar with comment functionality enabled on event pages.
2. Attacker crafts a malicious payload disguised as block markup intended to trigger the deserialization flaw.
3. Attacker submits a new comment on an event page containing the malicious payload.
4. Attacker utilizes the WordPress moderation-hash URL to access and trigger the rendering of their own pending comment.
5. The plugin's V2 single-event template calls `do_blocks()` on the buffered comment HTML during the rendering process.
6. The `is_safe_widget_instance` function is invoked, and the attacker-forged `wp_hash` attribute bypasses existing integrity checks.
7. The application reaches the `unserialize()` function with the attacker-controlled input, leading to arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-78006 allows unauthenticated attackers to execute arbitrary code with the privileges of the web server process. This can lead to full site compromise, data exfiltration, and lateral movement within the hosting environment. All WordPress sites utilizing The Events Calendar version 6.17.4 or earlier are at risk if comments are enabled on event pages.

## Recommendation

* Immediately update The Events Calendar plugin to the latest version, ensuring all installations are beyond version 6.17.4.
* As a temporary mitigation, disable comments on all event-related posts until the plugin has been patched.
* Audit web server logs for suspicious HTTP POST requests directed toward comment submission endpoints that contain unexpected block-like serialized strings or PHP magic method patterns.
