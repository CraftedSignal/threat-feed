---
title: CVE-2026-89036 Argument Injection in Appwrite
slug: 2026-09-appwrite-argument-injection
description: Authenticated users can achieve remote code execution in Appwrite versions before 2.0.0 by exploiting an argument injection vulnerability via the providerRootDirectory parameter in GNU tar commands.
date: "2026-09-17T17:58:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:appwrite:appwrite:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - argument-injection
  - appwrite
vendors:
  - Appwrite
products:
  - Appwrite (< 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users with functions.write or sites.write permissions to execute arbitrary commands by injecting TAB characters.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The application uses escapeshellcmd instead of escapeshellarg and fails to quote the parameter... enabling injection of arbitrary GNU tar arguments.
    confidence_band: high
cves:
  - id: CVE-2026-89036
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89036
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Appwrite to version 2.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability entry explicitly identifies 2.0.0 as the remediation version
  hunt_leads:
    - lead: Search logs for unusual tar command arguments in process creation telemetry
      technique_id: T1059.003
      data_needed:
        - CommandLine
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source explicitly names '--checkpoint-action=exec' as an injection target
  mitigation_plan:
    - priority: immediate
      action: Upgrade Appwrite to 2.0.0
      owner: IT Operations
      addresses: CVE-2026-89036
      evidence: NVD advisory
---

Appwrite versions prior to 2.0.0 contain a critical argument injection vulnerability (CVE-2026-89036) that permits authenticated users with functions.write or sites.write permissions to achieve remote code execution (RCE). The vulnerability stems from the improper sanitization of the providerRootDirectory parameter, which is passed to system commands executing GNU tar. Specifically, the application utilizes the PHP function escapeshellcmd rather than escapeshellarg and fails to wrap the parameter in quotes. This allows an attacker to inject TAB characters, which bypass existing filters and are interpreted as argument separators by the underlying shell. By injecting arbitrary GNU tar arguments, such as --checkpoint-action=exec, an attacker can execute arbitrary code under the context of the builds worker process user. This vulnerability is particularly significant due to the elevated privileges afforded to the builds worker process, potentially allowing for full system compromise within the Appwrite environment.

## Attack Chain

1. An attacker obtains or utilizes a valid account with 'functions.write' or 'sites.write' permissions.
2. The attacker interacts with the application API or UI to configure the 'providerRootDirectory' setting.
3. The attacker submits a specially crafted 'providerRootDirectory' payload containing one or more TAB characters (0x09) followed by malicious GNU tar flags.
4. The Appwrite application processes the input using 'escapeshellcmd', which fails to neutralize the injected TAB characters or prevent argument injection.
5. The application constructs a system command string including the tainted 'providerRootDirectory' parameter.
6. The shell executes the command, interpreting the TAB-separated segments as distinct arguments to the 'tar' binary.
7. The 'tar' binary processes the injected '--checkpoint-action=exec' flag.
8. The 'tar' utility spawns an external process to execute attacker-supplied commands, granting the attacker RCE as the 'builds worker' process user.

## Impact

Successful exploitation allows for remote code execution on the server running the Appwrite 'builds worker' process. This could lead to full compromise of the affected Appwrite installation, unauthorized access to sensitive application data, exfiltration of environment variables or secrets, and the potential for lateral movement within the hosting infrastructure.

## Recommendation

* Upgrade Appwrite to version 2.0.0 or later immediately to patch the argument injection vulnerability.
* Audit access logs for the 'functions.write' and 'sites.write' endpoints to identify suspicious attempts to modify configuration parameters containing control characters like TAB.
* Monitor the 'builds worker' process for the spawning of unexpected child processes or command-line execution patterns associated with 'tar' flags such as '--checkpoint-action'.
* Restrict permissions for users within the Appwrite console, ensuring the principle of least privilege is applied to those with configuration write access.
