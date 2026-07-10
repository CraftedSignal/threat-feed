---
title: CircleCI Security Step Disabled Detection
slug: 2024-01-circleci-security-disable
description: Detection of disabling security steps in CircleCI, potentially indicating an attempt to bypass security controls during the CI/CD process.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - circleci
  - ci/cd
  - devops
  - security-bypass
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
  - title: Detect CircleCI Configuration Changes
    description: Detects changes to CircleCI configuration files, which could indicate an attempt to disable security steps.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - file_event
      - linux
  - title: Detect CircleCI Disable Security Step
    description: Detects attempts to disable security steps within CircleCI configuration files by identifying keywords associated with security-related actions being commented out or removed.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This brief focuses on the detection of actions that disable security steps within CircleCI. While the specific actor remains unknown, the activity itself is indicative of a potential insider threat or compromised account attempting to weaken security measures. The goal could be to introduce malicious code, bypass security scans, or exfiltrate sensitive data without detection. By disabling security steps, attackers can create a blind spot, making it significantly harder to identify and prevent malicious activities within the CI/CD pipeline. This activity should be treated with a high degree of suspicion.

## Attack Chain

1. **Compromise Account:** An attacker gains unauthorized access to a CircleCI account with sufficient privileges to modify project settings.
2. **Identify Security Steps:** The attacker enumerates the defined security steps within the CircleCI configuration files (e.g., `.circleci/config.yml`).
3. **Modify Configuration:** The attacker modifies the CircleCI configuration files to disable specific security steps, such as vulnerability scanning, code analysis, or secret scanning.
4. **Commit Changes:** The attacker commits the modified configuration files to the project's repository.
5. **Trigger Build:** The changes trigger a new build in CircleCI, which now executes without the disabled security steps.
6. **Deploy Malicious Code (Optional):** If the disabled security steps were intended to prevent the introduction of malicious code, the attacker may now introduce it without immediate detection.
7. **Exfiltration (Optional):** If the disabled security steps were intended to prevent data exfiltration, the attacker can now potentially exfiltrate sensitive data.
8. **Maintain Persistence:** The attacker might create backdoors or alter other configurations to maintain long-term access and control over the CI/CD pipeline.

## Impact

A successful attack involving the disabling of security steps in CircleCI can lead to the introduction of vulnerabilities into production systems, data breaches, and supply chain attacks. The impact can range from defacement of websites to complete compromise of critical infrastructure. The number of victims can vary depending on the scope of the compromised CI/CD pipeline, from a single internal application to a widely distributed software product affecting thousands of users.

## Recommendation

*   Implement multi-factor authentication (MFA) for all CircleCI accounts to mitigate account compromise (reference: any CircleCI documentation on MFA).
*   Monitor CircleCI audit logs for configuration changes that disable security-related steps (reference: CircleCI audit log documentation, implement detections based on modifications of `.circleci/config.yml`).
*   Implement the Sigma rule `Detect CircleCI Configuration Changes` to detect modifications of CircleCI config files.
*   Implement the Sigma rule `Detect CircleCI Disable Security Step` to detect disabling of security steps based on modifications to `.circleci/config.yml`.
