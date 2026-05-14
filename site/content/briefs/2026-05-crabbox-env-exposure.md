---
title: Crabbox Environment Variable Exposure Vulnerability (CVE-2026-8634)
slug: 2026-05-crabbox-env-exposure
description: Crabbox prior to v0.12.0 is vulnerable to environment variable exposure, allowing attackers with access to a malicious repository to forward local secrets into the remote command environment by exploiting overly permissive environment variable allowlisting and serializing sensitive environment variables into remote command execution, exposing credentials to the remote environment.
date: "2026-05-14T20:21:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - environment variable exposure
  - credential theft
  - remote command execution
  - CVE-2026-8634
products:
  - Crabbox < 0.12.0
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.008
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-8634
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8634
rules:
  - title: Detect Suspicious Crabbox Environment Variable Exposure
    description: Detects CVE-2026-8634 exploitation — Attempts to define overly permissive environment variable allowlists in `crabbox.yaml` configurations that include sensitive credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.008
    data_sources:
      - file_event
      - linux
  - title: Detect Crabbox Remote Command Execution with Exposed Credentials
    description: Detects command execution within Crabbox containers where sensitive environment variables related to cloud or broker access are present, potentially indicating credential theft post CVE-2026-8634 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - execution
    techniques:
      - T1003
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Crabbox, a tool used for managing and orchestrating containerized applications, is susceptible to an environment variable exposure vulnerability (CVE-2026-8634) in versions prior to v0.12.0. This vulnerability enables attackers with access to a malicious or compromised repository to forward local secrets such as API tokens, cloud credentials, and broker tokens into the remote command environment. The root cause lies in the overly permissive environment variable allowlisting in repo-local Crabbox configurations. By exploiting this, attackers can serialize sensitive environment variables into remote command execution, ultimately exposing credentials to the remote environment. This presents a significant risk to organizations utilizing Crabbox, potentially leading to unauthorized access to critical resources and data breaches.

## Attack Chain

1.  Attacker gains access to a repository using Crabbox. This could be achieved via compromised credentials or by contributing to a public repository.
2.  Attacker crafts or modifies the `crabbox.yaml` configuration file within the repository.
3.  The `crabbox.yaml` file is configured with an overly permissive environment variable allowlist, specifically targeting sensitive environment variables such as cloud credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), API tokens, and broker tokens.
4.  The attacker triggers a Crabbox command execution (e.g., `crabbox run`) that utilizes the configured environment variables.
5.  Crabbox serializes the environment variables defined in the allowlist and passes them to the remote command execution environment.
6.  The remote command execution environment now has access to the sensitive environment variables.
7.  Attacker executes commands within the remote environment to extract or utilize the exposed credentials.
8.  The attacker uses the stolen credentials to gain unauthorized access to cloud resources, internal systems, or third-party services, achieving the objective of data exfiltration or lateral movement.

## Impact

Successful exploitation of CVE-2026-8634 can lead to the exposure of sensitive credentials, granting attackers unauthorized access to critical infrastructure and data. The impact can range from data breaches and service disruptions to complete system compromise. The severity is heightened by the potential for lateral movement and privilege escalation within the compromised environment. Organizations utilizing vulnerable versions of Crabbox are at risk. A CVSS v3.1 base score of 9.1 reflects the high potential for damage.

## Recommendation

*   Upgrade Crabbox to version 0.12.0 or later to remediate CVE-2026-8634.
*   Review and restrict the environment variable allowlist in `crabbox.yaml` configurations to the minimum required set of variables. Avoid using overly permissive wildcards or patterns that could expose sensitive data.
*   Implement the Sigma rule "Detect Suspicious Crabbox Environment Variable Exposure" to detect attempts to exploit this vulnerability via malicious configurations.
*   Monitor process execution within Crabbox containers for suspicious activities indicative of credential harvesting or unauthorized access attempts using "Detect Crabbox Remote Command Execution with Exposed Credentials".
*   Enable detailed logging of Crabbox command execution and configuration changes to facilitate incident response and forensic analysis.
