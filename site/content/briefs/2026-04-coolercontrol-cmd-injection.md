---
title: CoolerControl Command Injection Vulnerability (CVE-2026-5208)
slug: 2026-04-coolercontrol-cmd-injection
description: CoolerControl/coolercontrold versions before 4.0.0 are vulnerable to command injection, allowing authenticated attackers with high privileges to execute arbitrary code as root by injecting bash commands into alert names.
date: "2026-04-08T12:16:22Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - privilege-escalation
  - coolercontrol
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-5208
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5208
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/3.1.0/coolercontrold/src/alerts.rs?ref_type=tags#L576
  - https://gitlab.com/coolercontrol/coolercontrol/-/releases/4.0.0
rules:
  - title: Detect Suspicious Alert Creation
    description: Detects creation of alerts with potentially malicious commands in the name field.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Process Spawned by coolercontrold
    description: Detects suspicious processes spawned by coolercontrold, indicating potential command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CoolerControl/coolercontrold, a system monitoring and management tool, is susceptible to a command injection vulnerability (CVE-2026-5208) in versions prior to 4.0.0. The vulnerability stems from insufficient sanitization of user-supplied input used to create alert names. An authenticated attacker with high privileges can inject arbitrary bash commands into the alert name field. Due to the application's execution context, these injected commands are executed with root privileges, potentially leading to complete system compromise. The vulnerability was reported and patched in version 4.0.0. This poses a significant risk to organizations using affected versions of CoolerControl/coolercontrold, as it allows for trivial privilege escalation and arbitrary code execution.

## Attack Chain

1. Attacker authenticates to the CoolerControl/coolercontrold application with high-privilege credentials.
2. Attacker navigates to the alert configuration section of the application.
3. Attacker crafts a malicious alert name containing injected bash commands (e.g., `test; rm -rf /;`).
4. Attacker saves the new alert configuration with the injected command in the alert name.
5. When the alert is triggered or processed by the application, the injected command is executed within the context of the CoolerControl/coolercontrold process.
6. Due to insufficient input validation, the operating system executes the injected command, in this example `rm -rf /` which would recursively delete every file on the system.
7. The injected commands are executed with root privileges, resulting in arbitrary code execution.
8. The attacker gains complete control of the system.

## Impact

Successful exploitation of CVE-2026-5208 allows an attacker to execute arbitrary code with root privileges on the affected system. This could lead to complete system compromise, including data theft, data destruction, denial of service, and the installation of backdoors or other malicious software. Since this can be exploited via an application setting, a wide range of systems could be impacted.

## Recommendation

*   Upgrade CoolerControl/coolercontrold to version 4.0.0 or later to patch CVE-2026-5208, as mentioned in the vulnerability description.
*   Deploy the Sigma rule `Detect Suspicious Alert Creation` to identify attempts to inject commands into alert names.
*   Monitor process creation events for suspicious commands executed by the CoolerControl/coolercontrold process. Enable Sysmon process-creation logging to facilitate this.
*   Review existing alert configurations for any suspicious or unexpected commands.
