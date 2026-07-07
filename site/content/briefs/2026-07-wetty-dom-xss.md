---
title: Wetty Client DOM XSS via Base64 Filename in File Download Escape Sequence (CVE-2026-49864)
slug: 2026-07-wetty-dom-xss
description: A high-severity DOM XSS vulnerability (CVE-2026-49864) in the wetty SSH client allows an attacker to achieve keystroke injection and command execution on the victim's SSH session by embedding a crafted base64-encoded filename within a terminal file-download escape sequence, which is then unescaped and rendered as raw HTML.
date: "2026-07-03T12:42:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - dom-xss
  - wetty
  - vulnerability
  - rce
  - ssh-client
  - client-side
products:
  - wetty (< 3.0.4)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The wetty client decodes a base64 filename from the file-download escape sequence and interpolates it raw into a Toastify HTML string (`escapeMarkup: false`)... scripts in the wetty origin'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '`window.wetty_term.input("id > /tmp/pwned\n",true)` fires xterm.js''s `onData`, which `src/client/wetty.ts:40-42` forwards as a socket `input` event - i.e., script in the wetty origin types into the victim''s SSH session.'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 'The SSH host runs `id > /tmp/pwned` as the connected user: `cat /tmp/pwned` Expected: `uid=1000(term) gid=1000(term) groups=1000(term)`.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The wetty client decodes a base64 filename from the file-download escape sequence... Any output the victim renders... runs script in the wetty origin
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p26j-h7wj-r568
rules:
  - title: Detect Wetty DOM XSS Payload Injection Attempt
    description: Detects attempts to inject the wetty DOM XSS payload (CVE-2026-49864) by looking for specific `printf` commands that embed the file-download escape sequence with a base64-encoded filename.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059.004
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical DOM-based Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-49864, has been identified in the wetty web-based SSH client, affecting versions prior to 3.0.4. This flaw allows a remote attacker to execute arbitrary JavaScript within the victim's browser context, leading to keystroke injection and command execution within their active SSH session. The vulnerability stems from wetty's client-side handling of file-download escape sequences (`\x1b[5i...:...\x1b[4i`), where a base64-encoded filename within the sequence is directly base64-decoded and interpolated into an HTML `Toastify` notification with `escapeMarkup: false`. This allows an attacker to inject malicious HTML, including `<script>` tags or `onerror` event handlers, into the victim's browser. The exploitation occurs when the victim's terminal renders any output containing the specially crafted escape sequence, making it a significant threat to confidentiality and integrity of SSH sessions.

## Attack Chain

1.  **Attacker gains control of SSH server output**: The attacker compromises an SSH server that the victim uses with wetty, or is another user on a shared SSH host who can write to files/logs visible to the victim.
2.  **Attacker crafts malicious escape sequence**: The attacker prepares a base64-encoded HTML payload (e.g., `<img src=x onerror="window.wetty_term.input(\"cmd\\n\",true)">`) and encodes it as the filename portion of a file-download escape sequence.
3.  **Attacker delivers escape sequence to terminal output**: The attacker uses a command like `printf '\x1b[5i%s:%s\x1b[4i' "$FNAME_B64" "$DATA_B64"` to emit the crafted escape sequence into the victim's SSH session output (e.g., by `cat`ting a file, tailing a log, or via MOTD).
4.  **Victim's wetty client processes output**: The wetty client receives the terminal output containing the escape sequence and passes it through its `FileDownloader.buffer`.
5.  **Malicious filename is decoded and rendered**: The `FileDownloader` identifies the complete escape sequence, base64-decodes the filename, and interpolates it unescaped into a `Toastify` notification, which renders the attacker-controlled HTML.
6.  **XSS payload executes in victim's browser**: The injected HTML (e.g., the `onerror` handler) executes, calling `window.wetty_term.input()` with attacker-chosen commands.
7.  **Commands are typed into victim's SSH session**: The `wetty_term.input()` method causes the attacker's commands to be sent to the SSH server as if the victim typed them, leading to execution (e.g., `id > /tmp/pwned`).
8.  **Information disclosure/further compromise**: The attacker-injected commands execute on the SSH host, potentially leading to data exfiltration (e.g., `window.wetty_term.buffer.active` disclosure) or further system compromise.

## Impact

This vulnerability poses a severe risk to organizations using vulnerable wetty clients. If exploited, it grants the attacker significant control over the victim's SSH session. Impact includes compromise of confidentiality, as the attacker can read the victim's rendered terminal contents via `window.wetty_term.buffer.active`. Integrity is also compromised through the ability to type arbitrary attacker-chosen commands into the victim's SSH session via `window.wetty_term.input()`, effectively achieving remote command execution. Furthermore, it presents a critical authentication bypass, allowing an attacker who can control terminal output (e.g., a low-privileged user on a shared SSH host) to gain keystroke injection capabilities into a higher-privileged user's wetty session, escalating privileges or moving laterally within the environment.

## Recommendation

*   Patch CVE-2026-49864 by upgrading the wetty client to version 3.0.4 or later immediately.
*   Deploy the Sigma rule provided in this brief to your SIEM to detect attempts to inject malicious escape sequences via `printf` or similar commands within SSH sessions.
*   Review SSH server command logging for unusual `printf` commands containing `\x1b[5i` and base64-encoded strings, as detected by the rule `Detect Wetty DOM XSS Payload Injection Attempt`.
