---
title: Detection of Suspicious Double Extension File Names
slug: 2026-09-suspicious-double-extensions
description: Adversaries frequently employ files with double extensions to bypass user skepticism and exploit Windows default settings that hide common file extensions.
date: "2026-09-03T13:37:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stealth
  - file-masquerading
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.
    confidence_band: high
references:
  - https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/
  - https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
  - https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles
rules:
  - title: Detect Suspicious Double Extension Files
    description: Detects dropped files with double extensions often used by malware to bypass user scrutiny
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1036.007
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect files with double extensions
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Enable Windows GPO 'Show file extensions'
      owner: IT Operations
      addresses: T1036.007
      evidence: Source notes Windows hides extensions by default
---

Threat actors, including groups like Mustang Panda and operators of the BazarLoader malware, utilize file masquerading techniques to deceive users into executing malicious binaries. By crafting filenames with double extensions (e.g., 'document.pdf.exe'), attackers take advantage of the default Windows configuration that hides known file extensions from the user interface. This makes a malicious executable appear as a harmless document or media file. The technique is frequently used in spear-phishing campaigns to deliver payloads, such as droppers or remote access trojans (RATs). Detection engineering teams should monitor for the creation of files with mismatched or dual-extension patterns, as this is a high-fidelity indicator of social engineering and malicious intent.

## Impact

Successful execution of these files leads to unauthorized code execution, potential establishment of persistence, and subsequent compromise of host systems. Observed campaigns targeting government, private sector, and minority groups demonstrate that this technique is a reliable vector for gaining initial access to sensitive environments.

## Recommendation

1. Deploy the provided Sigma rule to your SIEM/EDR to monitor for file creation events that match suspicious double-extension patterns.
2. Implement Group Policy settings to "Show file extensions" globally, reducing the efficacy of this masquerading technique for end-users.
3. Configure endpoint security solutions to alert on or block files that use high-risk combinations like '.zip.exe' or '.rar.exe' which are explicitly designed for evasion.
4. Use the file_event logs to baseline common legitimate software update patterns to tune out noise and reduce false positives in highly dynamic environments.
