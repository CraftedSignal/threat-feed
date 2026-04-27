---
title: Notepad++ Updater (gup.exe) Creates Uncommon Files
slug: 2026-06-notepadpp-updater-file-creation
description: The Notepad++ updater (gup.exe) creating files in suspicious locations can indicate potential exploitation for malware delivery or unwarranted file placement, potentially leading to credential access and collection.
date: "2026-04-21T10:34:51Z"
severities:
  - high
tags:
  - supply-chain
  - malware
  - notepad++
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary in the Middle
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://notepad-plus-plus.org/news/v889-released/
  - https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
  - https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
  - https://securelist.com/notepad-supply-chain-attack/118708/
rules:
  - title: Notepad++ Updater (gup.exe) Creates Uncommon Files
    description: Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential-access
      - initial-access
    techniques:
      - T1195.002
      - T1557
    data_sources:
      - file_event
      - windows
  - title: Suspicious File Creation in Recycle Bin by Notepad++ Updater
    description: Detects when the Notepad++ updater (gup.exe) attempts to create files within the Recycle Bin directory, which is highly unusual behavior.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Notepad++ updater, `gup.exe`, is a component designed to automatically update the Notepad++ application. However, attackers can potentially exploit this updater to deliver malware or place unwarranted files on a system. This activity often begins with a compromised update server or a man-in-the-middle attack. Successful exploitation can lead to the installation of backdoors, credential access, and collection of sensitive information. The references provided highlight historical incidents…
