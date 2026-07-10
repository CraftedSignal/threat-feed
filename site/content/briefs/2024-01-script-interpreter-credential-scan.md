---
title: Script Interpreter Spawning Credential Scanner
slug: 2024-01-script-interpreter-credential-scan
description: A script interpreter such as node.exe or bun.exe spawning a credential scanning tool like trufflehog or gitleaks indicates potential credential compromise, as seen in the Shai-Hulud campaign.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - malware
  - windows
vendors:
  - npm Inc.
  - GitHub
  - Zapier
  - Ethereum Name Service
products:
  - npm
  - GitHub
  - Zapier
  - ENS Domains
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/asyncapi/cli/blob/2efa4dff59bc3d3cecdf897ccf178f99b115d63d/bun_environment.js
  - https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised
  - https://www.endorlabs.com/learn/shai-hulud-2-malware-campaign-targets-github-and-cloud-credentials-using-bun-runtime
  - https://semgrep.dev/blog/2025/digging-for-secrets-sha1-hulud-the-second-coming-of-the-npm-worm/
rules:
  - title: Script Interpreter Spawning TruffleHog
    description: Detects a script interpreter spawning TruffleHog, a credential scanning tool.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential-access
      - execution
    techniques:
      - T1005
      - T1059.007
      - T1552
    data_sources:
      - process_creation
      - windows
  - title: Script Interpreter Spawning GitLeaks
    description: Detects a script interpreter spawning GitLeaks, a credential scanning tool.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential-access
      - execution
    techniques:
      - T1005
      - T1059.007
      - T1552
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly leveraging script interpreters like Node.js and Bun to execute credential scanning tools within compromised environments. This tactic allows them to search for exposed secrets, API keys, and other sensitive information stored in configuration files, source code, or other accessible locations. The "Shai-Hulud: The Second Coming" campaign exemplifies this trend, where compromised npm packages were used to execute malicious code, ultimately leading to credential theft. The use of credential scanners like TruffleHog and GitLeaks automates the process of identifying these secrets, making it easier for attackers to escalate their access and compromise sensitive data. Defenders should be alert to script interpreters spawning credential scanning tools to mitigate the risk of credential theft.

## Attack Chain

1.  A user downloads and installs a malicious or compromised package containing malicious JavaScript code.
2.  The malicious package is executed via a script interpreter such as `node.exe` or `bun.exe`.
3.  The script interpreter process spawns a credential scanning tool, such as `trufflehog.exe` or `gitleaks.exe`.
4.  The credential scanner searches local directories, file systems, and potentially network shares for exposed secrets.
5.  Any identified credentials are then exfiltrated by the attacker.
6.  The attacker uses the stolen credentials to gain unauthorized access to systems, applications, or data.
7.  The attacker may further escalate privileges and compromise other parts of the environment.

## Impact

Successful exploitation can lead to the compromise of sensitive credentials, allowing attackers to gain unauthorized access to critical systems and data. This can result in data breaches, financial losses, reputational damage, and disruption of services. The "Shai-Hulud" campaign targeted GitHub and cloud credentials, potentially impacting numerous organizations that rely on these services. The number of affected organizations is difficult to quantify but given the widespread use of npm packages, the potential impact is significant.

## Recommendation

*   Deploy the Sigma rule `Script Interpreter Spawning Credential Scanner` to your SIEM to detect suspicious process creation events involving script interpreters and credential scanning tools.
*   Monitor process creation logs for script interpreters spawning child processes associated with credential scanning tools.
*   Implement strict input validation and sanitization practices to prevent the injection of malicious code into script interpreters.
*   Regularly scan your codebase and infrastructure for exposed secrets using dedicated secret scanning tools.
*   Enforce the principle of least privilege to limit the potential impact of compromised credentials.
