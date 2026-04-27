---
title: NICKEL ALLEY Targeting Developers with Fake Job Opportunities
slug: 2026-05-nickel-alley
description: NICKEL ALLEY, a North Korean threat group, is targeting technology professionals with fake job opportunities and malicious code repositories to deliver malware like PyLangGhost RAT and BeaverTail, aiming to steal cryptocurrency.
date: "2026-03-25T10:25:17Z"
severities:
  - high
actors:
  - NICKEL ALLEY
tags:
  - NICKEL ALLEY
  - North Korea
  - cryptocurrency
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.sophos.com/en-us/blog/nickel-alley-strategy-fake-it-til-you-make-it
ioc_counts:
  domain: 4
rules:
  - title: Detect NICKEL ALLEY VBScript ClickFix
    description: Detects the VBScript execution in the %TEMP% folder followed by the execution of a renamed python.exe (csshost.exe) as part of a ClickFix infection chain used by NICKEL ALLEY.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
  - title: Detect NICKEL ALLEY Outbound Connection
    description: Detects suspicious outbound connections from unusual processes to newly registered domains, indicative of NICKEL ALLEY activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

NICKEL ALLEY, a threat group operating on behalf of the North Korean government, continues to target professionals in the technology sector using sophisticated social engineering tactics. Since at least mid-2025, the group has been observed creating fake LinkedIn company pages, GitHub repositories, and job opportunities to deceive prospective candidates and deliver malware. They employ tactics such as "ClickFix," where victims are tricked into running malicious commands under the guise of…
