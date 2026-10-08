---
title: Argument Injection in ILIAS assImagemapQuestionGUI
slug: 2026-10-ilias-arg-injection
description: An argument injection vulnerability in the ILIAS assImagemapQuestionGUI component allows authenticated question authors to achieve remote code execution by injecting ImageMagick options via crafted filenames.
date: "2026-10-08T17:11:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ilias:ilias:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - vulnerability
vendors:
  - ILIAS
products:
  - ILIAS (< 9.24, 10.x < 10.12, 11.x < 11.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ILIAS... contains an argument injection vulnerability... that allows question authors to inject ImageMagick convert options.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Attackers can embed tab-separated options... to write a PHP file under the web root and achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-107639
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107639
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ILIAS to version 9.24, 10.12, or 11.5
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-107639 patch requirements
  hunt_leads:
    - lead: Search web logs for suspicious files created in ILIAS upload directories
      technique_id: T1202
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker writes PHP file to web root
  mitigation_plan:
    - priority: immediate
      action: Upgrade ILIAS to 9.24 or later
      owner: IT Operations
      addresses: CVE-2026-107639
      evidence: Official NVD vulnerability report
---

ILIAS, an open-source learning management system, contains an argument injection vulnerability identified as CVE-2026-107639, affecting versions before 9.24, 10.x before 10.12, and 11.x before 11.5. The vulnerability resides within the `assImagemapQuestionGUI` component, which handles image uploads for question-based assessments. Attackers with permission to author questions can upload image files with specially crafted, tab-separated filenames. Because the application's implementation of `escapeshellcmd()` fails to neutralize these injected arguments, the underlying ImageMagick `convert` utility treats the filename segments as functional command-line options. By manipulating these options, an attacker can force the utility to write arbitrary content to a file, such as a PHP shell, within the web-accessible directory. Successful exploitation results in full remote code execution under the privileges of the web server process.

## Attack Chain

1. The attacker authenticates to the ILIAS platform with question authoring privileges.
2. The attacker creates a new ImageMap question or modifies an existing one.
3. The attacker prepares a malicious image file where the filename contains tab-separated ImageMagick arguments.
4. The attacker uploads the crafted file to the `assImagemapQuestionGUI` interface.
5. The application passes the malicious filename directly to the ImageMagick `convert` utility on the host OS.
6. The `convert` utility interprets the injected arguments, triggering a file write operation to a location under the web root.
7. The attacker browses to the newly created, malicious PHP file via the web browser.
8. The server executes the embedded PHP code, providing the attacker with remote code execution.

## Impact

The vulnerability allows an authenticated attacker to execute arbitrary code on the host server. This impact is critical for institutional deployments of ILIAS, as compromised instances may grant attackers access to sensitive student data, grades, and potentially administrative credentials for connected authentication systems. All versions of ILIAS below 9.24, 10.12, and 11.5 are considered vulnerable.

## Recommendation

1. Upgrade all ILIAS instances to version 9.24, 10.12, 11.5, or later immediately to patch CVE-2026-107639.
2. Audit web server access logs for anomalous requests targeting newly created files or files with unexpected extensions within the ILIAS upload directories.
3. Restrict question authoring privileges to trusted users until the software has been updated.
4. Ensure that the ImageMagick `convert` utility is restricted from performing file-write operations outside of designated temporary directories using security policy configurations.
