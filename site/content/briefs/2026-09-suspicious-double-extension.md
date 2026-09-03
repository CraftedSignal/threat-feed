---
title: Suspicious Double Extension File Execution Patterns
slug: 2026-09-suspicious-double-extension
description: Threat actors utilize deceptive filenames with double extensions or whitespace padding to trick users into executing malicious binaries via spearphishing campaigns.
date: "2026-09-03T12:45:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - initial-access
  - phishing
  - evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
    confidence_band: high
references:
  - https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
  - https://twitter.com/blackorbird/status/1140519090961825792
  - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
rules:
  - title: Detect Suspicious Double Extension File Execution
    description: Detects the use of non-executable file extensions followed by an executable extension, or whitespace/underscore padding to cloak a malicious binary.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
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
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides actionable Sigma detection logic.
  hunt_leads:
    - lead: Search logs for process execution paths containing multiple file extensions or whitespace cloaking.
      technique_id: T1566.001
      data_needed:
        - Process creation events (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a common spearphishing technique.
---

Attackers frequently employ deceptive naming conventions to facilitate the execution of malicious payloads, particularly in spearphishing campaigns. By appending non-executable extensions - such as .pdf, .docx, or .jpg - followed by an actual executable extension like .exe or .js, adversaries aim to exploit user reliance on visible file extensions to mask the true nature of a malicious file. In some cases, attackers use excessive whitespace, underscores, or Unicode characters (e.g., the Braille Pattern Blank) to push the actual extension outside the default Windows Explorer view. This technique is designed to bypass basic user scrutiny when attachments are downloaded and opened. Detection engineering teams should focus on process creation events where the image path or command line arguments contain these specific deceptive patterns, as they are rarely used by legitimate enterprise software.

## Attack Chain

1. Attacker prepares a malicious binary disguised with a double extension (e.g., invoice.pdf.exe).
2. Attacker hosts the file on an infrastructure site or embeds it within an email attachment.
3. Victim receives the file and, due to the deceptive name, perceives it as a benign document.
4. Victim executes the file via the Windows shell (explorer.exe).
5. The Windows process creation event captures the execution path.
6. The malicious process launches, potentially initiating secondary payload download or system enumeration.
7. Final objective is achieved, such as credential theft, ransomware deployment, or data exfiltration.

## Impact

This technique facilitates unauthorized code execution on victim endpoints. If successful, it allows attackers to establish persistent access, conduct reconnaissance within the internal network, and exfiltrate sensitive data. These campaigns often target a broad range of sectors, focusing on users who regularly handle external documents.

## Recommendation

1. Deploy the provided Sigma rule to detect process creation events containing common deceptive filename patterns.
2. Enable Sysmon Event ID 1 (Process Creation) to gain visibility into the 'Image' and 'CommandLine' fields necessary for identifying these patterns.
3. Perform threat hunting across existing logs for files executing with the identified deceptive suffixes.
4. Implement security awareness training to educate users on Windows file extension visibility settings.
