---
title: NICKEL ALLEY Targeting Developers with Fake Job Opportunities
slug: 2026-05-nickel-alley
description: NICKEL ALLEY, a North Korean threat group, is targeting technology professionals with fake job opportunities and malicious code repositories to deliver malware like PyLangGhost RAT and BeaverTail, aiming to steal cryptocurrency.
date: "2026-03-25T10:25:17Z"
type: threat
types:
  - threat
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
iocs:
  - type: domain
    value: talentacq[.]pro
  - type: domain
    value: publicshare[.]org
  - type: domain
    value: astrabytesyncs[.]com
  - type: domain
    value: astra[.]com
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

NICKEL ALLEY, a threat group operating on behalf of the North Korean government, continues to target professionals in the technology sector using sophisticated social engineering tactics. Since at least mid-2025, the group has been observed creating fake LinkedIn company pages, GitHub repositories, and job opportunities to deceive prospective candidates and deliver malware. They employ tactics such as "ClickFix," where victims are tricked into running malicious commands under the guise of fixing technical issues. Additionally, they've compromised npm package repositories and used typosquatting to distribute malicious packages. The group leverages cloud platforms like Vercel for payload hosting, tailoring malware delivery based on victim system configurations. This activity is primarily motivated by cryptocurrency theft.

## Attack Chain

1.  **Initial Contact:** The attacker contacts a technology professional with a fake job opportunity, often advertised through LinkedIn or email.
2.  **Fake Company Profile:** The attacker establishes credibility by creating a fake company profile on LinkedIn and/or GitHub.
3.  **Malicious Repository:** The attacker creates a GitHub repository containing malicious code disguised as a software development project or crypto game (e.g., web3-social-platform).
4.  **ClickFix Delivery (PyLangGhost RAT):** During a fake interview process, the attacker instructs the victim to perform a "fix" by running a command which downloads and executes a VBScript file.
5.  **VBScript Execution:** The VBScript file (e.g., update.vbs, start.vbs) decompresses an archive (Lib.zip) containing library files and executes a renamed Python interpreter (csshost.exe) with a malicious Python script (nvidia.py).
6.  **BeaverTail Delivery (GitHub):** The victim is convinced to clone the GitHub repository and execute commands like `npm install` and `npm start`. The `index.js` file retrieves the BeaverTail malware from a Base64-encoded URL hosted on Vercel.
7.  **Malware Execution:** PyLangGhost RAT or BeaverTail malware executes on the victim's system, enabling file exfiltration, arbitrary command execution, and system profiling.
8.  **Data Theft:** The malware targets browser credentials, cookies, and cryptocurrency wallet data, leading to financial theft.

## Impact

NICKEL ALLEY's activities primarily target software developers and blockchain professionals. Successful attacks lead to the compromise of developer systems, theft of sensitive credentials, and exfiltration of cryptocurrency. The group's persistent targeting of the technology sector highlights their continued focus on financial gain through cryptocurrency theft. Compromised systems can be used to further propagate attacks or to steal intellectual property.

## Recommendation

*   Monitor process creation events for the execution of `wscript.exe` launching VBScript files from the `%TEMP%` directory and followed by execution of renamed python.exe (csshost.exe) as described in the Attack Chain above. Deploy the Sigma rule `Detect NICKEL ALLEY VBScript ClickFix` to detect this activity.
*   Inspect network connections from unusual processes (not browsers or standard networking tools) to newly registered domains or infrastructure providers like Vercel, using the `Detect NICKEL ALLEY Outbound Connection` Sigma rule.
*   Block access to the IOC domains `talentacq[.]pro`, `publicshare[.]org`, and `astrabytesyncs[.]com` at the DNS resolver.
*   Educate employees, especially those in software development, about social engineering tactics such as fake job opportunities and the ClickFix technique.
