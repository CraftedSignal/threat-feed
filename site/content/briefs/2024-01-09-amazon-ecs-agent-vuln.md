---
title: Amazon ECS Agent for Windows Vulnerable to Command Injection
slug: 2024-01-09-amazon-ecs-agent-vuln
description: Amazon ECS Agent for Windows versions 1.47.0 through 1.102.2 are vulnerable to command injection via specially crafted credentials in the FSx Windows File Server volume mounting process, potentially allowing a remote authenticated attacker to execute shell commands with SYSTEM privileges.
date: "2026-05-07T01:22:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command injection
  - privilege escalation
  - cloud
vendors:
  - Amazon
products:
  - ECS Agent for Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-fc67-c4hg-q653
rules:
  - title: Detect Suspicious ECS Task Definition Registration
    description: Detects registration of ECS task definitions that contain suspicious characters or commands in the volume configuration, which may indicate a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - cloudtrail
      - cloudtrail
  - title: Detect Modification of Secrets Manager Secrets Used in FSx Volume Configurations
    description: Detects modifications to secrets stored in Secrets Manager that are used in FSx volume configurations, which could indicate an attempt to inject malicious commands.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - cloudtrail
      - cloudtrail
rules_count: 2
---

Amazon ECS Agent for Windows is susceptible to a command injection vulnerability within the FSx Windows File Server volume mounting process. This flaw, present in versions 1.47.0 through 1.102.2, allows a remote, authenticated attacker with the ability to register ECS task definitions or write to the Secrets Manager or SSM Parameter Store credentials used by the FSx volume configuration to execute arbitrary shell commands with SYSTEM privileges on the host. This is achieved through the use of specially crafted credentials within the ECS task definition, specifically the username field. Successful exploitation of this vulnerability could lead to complete compromise of the ECS Windows worker instance. The vulnerability was addressed in ECS agent version 1.103.0. ECS on Fargate is not affected.

## Attack Chain

1. An attacker gains access to an AWS account with permissions to register ECS task definitions or write to Secrets Manager or SSM Parameter Store.
2. The attacker crafts a malicious ECS task definition. This definition includes an FSx Windows File Server volume configuration with a specially crafted username field containing a command injection payload.
3. The attacker registers the crafted task definition with the ECS service using `ecs:RegisterTaskDefinition`.
4. When ECS attempts to mount the FSx volume, it retrieves the credentials from Secrets Manager or SSM Parameter Store.
5. Due to improper input validation, the command injection payload within the username field is executed by the Amazon ECS Agent for Windows.
6. The malicious command is executed with SYSTEM privileges on the underlying host.
7. The attacker leverages the SYSTEM privileges to install malware, exfiltrate data, or perform other malicious activities.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary commands with SYSTEM privileges on the affected ECS Windows worker instance. This could lead to complete system compromise, including data theft, malware installation, and denial of service. The scope of impact is limited to ECS Windows worker instances running vulnerable versions (1.47.0 through 1.102.2). ECS on Fargate is not affected.

## Recommendation

*   Upgrade to ECS agent version 1.103.0 or later on all ECS Windows worker instances to remediate the vulnerability.
*   Restrict `ecs:RegisterTaskDefinition` permissions to trusted IAM principals only to limit the ability to register malicious task definitions.
*   Restrict write access to Secrets Manager secrets and SSM Parameter Store parameters referenced in FSx volume configurations.
