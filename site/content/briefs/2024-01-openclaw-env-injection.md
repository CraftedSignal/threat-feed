---
title: OpenClaw Environment Variable Injection Vulnerability (CVE-2026-41294)
slug: 2024-01-openclaw-env-injection
description: OpenClaw before 2026.3.28 is vulnerable to environment variable injection by loading a .env file from the current working directory before trusted configuration, potentially allowing attackers to override runtime settings.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - environment-variable-injection
  - cve-2026-41294
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-41294
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41294
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect .env File Creation in OpenClaw Directories
    description: Detects the creation of .env files in directories commonly used by OpenClaw deployments, which could indicate an attempted environment variable injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
  - title: Detect .env File Modification in OpenClaw Directories
    description: Detects the modification of .env files in directories commonly used by OpenClaw deployments, which could indicate an attempted environment variable injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.28 are susceptible to environment variable injection due to insecure loading of configuration files. Specifically, the application loads a `.env` file from the current working directory before applying configurations from trusted state directories. This design flaw allows a malicious actor to inject arbitrary environment variables by placing a crafted `.env` file within a repository or workspace where OpenClaw is executed. Successful exploitation leads to the overriding of runtime configurations, including potentially security-sensitive environment settings, upon OpenClaw's startup. This vulnerability poses a significant risk to the application's integrity and security posture.

## Attack Chain

1.  Attacker identifies an OpenClaw deployment or development environment.
2.  Attacker crafts a malicious `.env` file containing environment variables designed to compromise OpenClaw's configuration.
3.  The attacker places the malicious `.env` file in the current working directory of the OpenClaw application. This could be achieved by compromising a repository where the application code resides or a shared workspace.
4.  OpenClaw application is started or restarted from the compromised working directory.
5.  Upon startup, OpenClaw loads the `.env` file from the current working directory.
6.  The malicious environment variables within the `.env` file override existing configurations or inject new settings, such as redirecting log files, modifying API endpoints, or disabling security features.
7.  OpenClaw operates with the attacker-controlled environment variables, potentially leading to data breaches, privilege escalation, or denial-of-service conditions.

## Impact

Successful exploitation of this vulnerability (CVE-2026-41294) allows attackers to manipulate OpenClaw's runtime behavior by injecting arbitrary environment variables. This can lead to a variety of adverse outcomes, including unauthorized access to sensitive data, modification of application settings, and potential compromise of the underlying system. The severity of the impact depends on the specific environment variables targeted and the privileges held by the OpenClaw application.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate the vulnerability (CVE-2026-41294).
*   Implement file integrity monitoring on OpenClaw's working directory to detect unauthorized creation or modification of `.env` files (file_event log source).
*   Deploy the Sigma rule provided below to detect suspicious processes creating or modifying `.env` files in OpenClaw deployment directories.
