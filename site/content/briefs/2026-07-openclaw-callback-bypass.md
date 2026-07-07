---
title: OpenClaw Telegram Callback Authorization Bypass (GHSA-w5ww-7chg-mxcq)
slug: 2026-07-openclaw-callback-bypass
description: A high-severity vulnerability (GHSA-w5ww-7chg-mxcq) in OpenClaw allows an unauthorized Telegram user to bypass the `commands.allowFrom` sender check via interactive callbacks, leading to unauthorized command execution on the OpenClaw Gateway.
date: "2026-07-03T11:57:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - telegram
  - callback
  - vulnerability
  - npm
vendors:
  - OpenClaw
products:
  - OpenClaw (<= 2026.5.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Telegram interactive callbacks could skip commands.allowFrom.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: this could trigger command behavior outside the configured Telegram sender allowlist.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: a Telegram user able to invoke an affected callback could mark the callback as an authorized sender before applying `commands.allowFrom`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w5ww-7chg-mxcq
---

A critical vulnerability (GHSA-w5ww-7chg-mxcq) exists in OpenClaw, affecting versions up to `2026.5.5`, which allows an authorization bypass in its Telegram interactive callback functionality. Discovered and published on 2026-07-02, this flaw permits a malicious Telegram user to invoke a callback that marks itself as an authorized sender, effectively circumventing the `commands.allowFrom` restriction. This means commands intended for execution only by trusted users can be triggered by unauthorized individuals. The vulnerability primarily impacts OpenClaw Gateway operators who have Telegram interactive callbacks enabled, potentially leading to unintended command execution and system compromise. Organizations using OpenClaw should prioritize patching to version `2026.5.6` or later to prevent unauthorized command invocation. The risk is high given the potential for unauthorized control over the Gateway through a simple callback.

## Attack Chain

1. Attacker identifies an OpenClaw Gateway instance that exposes Telegram interactive callbacks.
2. Attacker crafts a specialized Telegram interactive callback request, targeting a specific command.
3. The crafted callback is sent to the vulnerable OpenClaw Gateway's Telegram interface.
4. OpenClaw Gateway receives and processes the interactive callback.
5. Due to the vulnerability (GHSA-w5ww-7chg-mxcq), the internal logic incorrectly marks the callback sender as authorized.
6. The `commands.allowFrom` check, which should restrict command execution based on sender identity, is bypassed.
7. The attacker's command, embedded within or triggered by the callback, is executed by the OpenClaw Gateway.
8. Unauthorized command execution leads to the attacker achieving their objective, such as data manipulation, system configuration changes, or further compromise.

## Impact

If exploited, this vulnerability could trigger command behavior outside the configured Telegram sender allowlist, leading to unauthorized actions on the OpenClaw Gateway. The practical impact is contingent upon the specific configuration of the operator and the sensitivity of commands accessible via Telegram. While no specific victim count or sectors are mentioned, any organization utilizing vulnerable OpenClaw versions with Telegram interactive callbacks enabled faces a high risk of unauthorized control over their Gateway, potentially leading to data exfiltration, service disruption, or further network penetration.

## Recommendation

*   Upgrade `npm/openclaw` to version `2026.5.6` or later to remediate the vulnerability described in this brief.
*   As a temporary mitigation, restrict Telegram command callbacks to trusted chats until `npm/openclaw` can be patched, as recommended by the advisory.
*   Disable the interactive callbacks feature for `npm/openclaw` if it is not strictly needed, reducing the attack surface.
