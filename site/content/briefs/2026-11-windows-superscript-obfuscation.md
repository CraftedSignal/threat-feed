---
brief_id: brief-2026-11-16-windows-superscript-obfuscation
event_id: brief-2026-11-16-windows-superscript-obfuscation
revision: 1
activity_at: "2026-11-16T21:28:25Z"
title: Windows Command Line Obfuscation via Superscript Characters
slug: 2026-11-windows-superscript-obfuscation
description: Attackers are obfuscating command line arguments using Unicode superscript and modifier characters to evade string-based security detections while maintaining execution capability in Windows.
date: "2026-11-16T21:28:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection rule defined based on regex pattern provided in source.
tags:
  - defense-evasion
  - execution
  - obfuscation
  - windows
vendors:
  - Microsoft
products:
  - msiexec.exe
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027.010
    technique_name: Command Obfuscation
    evidence: Windows command line parsers such as msiexec.exe normalize these look-alike characters, so the argument still works while evading string-based detections.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This technique has been observed in ClickFix-style campaigns where victims paste a command into the Run dialog that silently installs a remote MSI package with msiexec.exe.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_command_line_obfuscation_via_superscript_characters.yml
rules:
  - title: Detect Windows Command Line Obfuscation via Superscript Characters
    description: Detects Windows system binaries executed with command line arguments containing Unicode superscript or modifier letter characters used to obfuscate commands.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect command lines containing Unicode superscript and modifier characters.
      owner: Detection Engineering
      due: 48h
      evidence: The technique relies on command line normalization to bypass string-based filters.
  hunt_leads:
    - lead: Search for process command lines containing non-ASCII Unicode characters within system directories.
      technique_id: T1027.010
      data_needed:
        - Sysmon Event ID 1
        - Security Event ID 4688
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This technique has been observed in ClickFix-style campaigns where victims paste a command into the Run dialog.
---

## Overview

Malicious actors are leveraging Unicode characters, specifically superscripts and modifier letters, to obfuscate command line arguments in Windows environments. This technique allows attackers to replace standard ASCII characters with look-alike Unicode equivalents. The Windows command line parser, including binaries such as msiexec.exe, normalizes these characters, allowing the intended command to execute successfully while bypassing traditional signature-based detection rules. This tradecraft has been documented in ClickFix-style campaigns, where users are prompted to copy and paste malicious commands that trigger silent installations of remote MSI packages.

## Impact

Successful exploitation allows attackers to execute arbitrary commands, such as silent MSI installations via msiexec.exe, while evading detection systems that rely on static string analysis.

## Recommendation

Detection teams should implement telemetry analysis to identify the presence of non-ASCII, superscript, or modifier characters within command line arguments of processes spawned from standard Windows system paths. Security teams should prioritize monitoring for the use of msiexec.exe with suspicious command line parameters as observed in ClickFix-style social engineering attacks.
