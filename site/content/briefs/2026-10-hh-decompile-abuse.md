---
title: Abuse of Compiled HTML Help Application for Decompilation
slug: 2026-10-hh-decompile-abuse
description: Threat actors, including APT41, abuse the native Windows HTML Help application (hh.exe) to decompile CHM files for staging malicious payloads or bypassing security controls.
date: "2026-10-12T18:24:40Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - APT41
  - Wicked Panda
  - BARIUM
  - Brass Typhoon
  - Winnti
  - Double Dragon
tags:
  - living-off-the-land
  - defense-evasion
  - windows
  - endpoint
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic detects the use of the decompile parameter with the HTML Help application (HH.exe).
    confidence_band: high
references:
  - https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
  - https://attack.mitre.org/techniques/T1218/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1218.001/T1218.001.yaml
rules:
  - title: Detect Suspicious HH.exe Decompile Usage
    description: Detects the use of the decompile parameter with the HTML Help application (hh.exe), which is an uncommon command line used to unpack CHM files for potentially malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to detect hh.exe decompile usage
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance
  hunt_leads:
    - lead: Search for instances of hh.exe executed with -decompile
      technique_id: T1218.001
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Analytic describes this as an uncommon command
---

The Microsoft HTML Help application (hh.exe) is a legitimate system binary that can be abused by attackers to perform unauthorized actions. By invoking the decompile parameter, an attacker can extract the contents of a Compiled HTML Help (.chm) file to a specified directory. This technique, documented as T1218.001, is often used as a proxy for execution or to unpack malicious payloads staged within seemingly benign help files. APT41 and other actors have historically utilized this mechanism to evade detection by leveraging a trusted, signed Windows binary to facilitate the delivery of secondary malware or configuration files. Defenders should prioritize monitoring for the infrequent use of the decompile switch in their endpoint environments.

## Attack Chain

1. Attacker crafts or obtains a malicious CHM file containing secondary payloads or scripts.
2. The malicious file is delivered to the target host via phishing or web download.
3. The attacker executes hh.exe via a command-line interface or script.
4. The command utilizes the -decompile flag: hh.exe -decompile &lt;output_dir> &lt;chm_file>.
5. The contents of the CHM are extracted to the filesystem.
6. The extracted payloads, often scripts or binaries, are executed to achieve the primary goal, such as establishing C2 or persistence.

## Impact

Successful abuse of this technique can allow attackers to bypass security restrictions by using a trusted system utility to drop malicious files. This facilitates further system compromise, persistence, and potential data exfiltration. While specific victim counts are not cited in current reports, the technique is a known component in the toolsets of advanced persistent threat groups.

## Recommendation

Deploy detection coverage for the command-line usage of hh.exe with the decompile parameter.

- Implement the provided Sigma rule to alert on suspicious process creation events.
- Enable Sysmon or EDR process-creation logging to capture full command-line arguments.
- Audit the use of CHM files within the environment to identify unexpected help file execution.
