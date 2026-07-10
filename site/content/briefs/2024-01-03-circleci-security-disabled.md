---
title: CircleCI Security Step Disabled
slug: 2024-01-03-circleci-security-disabled
description: An attacker disables security steps within CircleCI to potentially bypass security controls and introduce malicious code into the build pipeline.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - circleci
  - ci/cd
  - security-bypass
  - supply-chain
vendors:
  - CircleCI
products:
  - CircleCI
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/circle_ci_disable_security_step.yml
rules:
  - title: Detect CircleCI Configuration Changes Disabling Security Steps
    description: Detects modifications to the CircleCI configuration file that remove or comment out security-related steps.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
  - title: Detect suspicious CLI usage inside CircleCI runner to modify files
    description: Detect usage of commands like sed or echo to modify files in CircleCI
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief addresses the potential risk of an attacker disabling security steps within a CircleCI configuration. While the provided source material does not describe a specific actor or campaign, the ability to manipulate CI/CD pipeline configurations is a known attack vector. By removing or altering security checks, an attacker can introduce vulnerabilities, inject malicious code, or exfiltrate sensitive information. This type of attack can be difficult to detect because it occurs within the trusted environment of the CI/CD system. The scope of targeting would likely focus on organizations that rely heavily on CircleCI for their software development and deployment processes.

## Attack Chain

1. **Initial Access:** The attacker gains access to the CircleCI project's configuration, potentially through compromised credentials or a vulnerability in the CircleCI platform itself.
2. **Configuration Modification:** The attacker modifies the `.circleci/config.yml` file to remove or comment out security-related steps. This could include steps that run static analysis tools, vulnerability scanners, or code quality checks.
3. **Bypass Security Checks:** With the security steps disabled, the build pipeline no longer enforces the intended security controls.
4. **Code Injection:** The attacker introduces malicious code into the codebase, either directly or through a compromised dependency. This code could be designed to steal secrets, create backdoors, or perform other malicious activities.
5. **Automated Build and Deployment:** The modified code is automatically built and deployed through the CI/CD pipeline.
6. **Compromise Production Environment:** The malicious code is deployed to the production environment, allowing the attacker to gain unauthorized access to systems and data.

## Impact

Successful disabling of security steps in CircleCI can lead to significant consequences. An attacker could inject malicious code into production systems, potentially affecting thousands of users and causing severe financial and reputational damage. Stolen credentials, backdoors, and data breaches could be used for further attacks or sold on the dark web. The targeted sectors are broad, including any organization using CircleCI for software development, particularly those in sensitive industries like finance and healthcare. The impact could range from data theft and service disruption to complete system compromise.
