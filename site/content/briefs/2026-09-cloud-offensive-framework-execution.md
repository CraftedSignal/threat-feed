---
title: Detection of Offensive Cloud Framework Execution
slug: 2026-09-cloud-offensive-framework-execution
description: Adversaries utilize cloud enumeration and exploitation frameworks to perform reconnaissance and identify privilege escalation paths following the compromise of cloud credentials on endpoint devices.
date: "2026-09-29T04:12:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - execution
  - cloud
  - endpoint
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Adversaries run these after obtaining cloud credentials to map the compromised principal's effective permissions, discover privilege escalation paths, and pivot to the console.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Identifies execution of well-known cloud exploitation, enumeration, and attack-simulation frameworks... either as a standalone binary or through a Python... launcher.
    confidence_band: high
rules:
  - title: Detect Execution of Offensive Cloud Frameworks
    description: Detects the execution of known cloud enumeration and offensive frameworks on an endpoint by process name or by searching command line arguments passed to script interpreters.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.006
      - T1580
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to endpoints
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific tool list and command patterns
  hunt_leads:
    - lead: Search for unknown processes making extensive API calls to cloud providers
      technique_id: T1580
      data_needed:
        - CloudTrail API logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Frameworks generate bursts of Describe, List, and Get calls.
  mitigation_plan:
    - priority: immediate
      action: Rotate cloud credentials found on compromised endpoints
      owner: SOC
      addresses: Credential theft
      evidence: Treat any key used by the framework as compromised.
---

Adversaries frequently deploy automated offensive cloud security frameworks on compromised endpoints after obtaining initial cloud access. These tools are used to map the compromised principal's effective permissions, discover privilege escalation paths, and pivot into cloud management consoles. While these frameworks are vital for authorized red team engagements and cloud audits, their presence on an endpoint often indicates a post-compromise activity where an attacker seeks to deepen their control over the cloud environment.

Observed frameworks include Pacu (S1091), CloudFox, ScoutSuite, PMapper, Stratus Red Team, Prowler, and others. Defenders must distinguish between authorized security assessments and unauthorized attacker activity. Because these tools often rely on existing cloud credentials (found in files like `~/.aws/credentials` or environment variables) to perform bursts of enumeration calls, their execution is a high-signal indicator of active threat actor intent to escalate privileges or exfiltrate cloud-resident data.

## Attack Chain

1. Adversary gains initial access to an endpoint host via phishing or exploited web-facing services.
2. Adversary searches the host for cloud access keys, identity files, or environment variables containing credentials.
3. Adversary downloads or executes an offensive framework (e.g., Pacu or CloudFox) on the compromised host.
4. The framework is launched via a script interpreter (Python, pipx, uv, or Go) to avoid detection by basic file-name filters.
5. The tool queries cloud APIs (e.g., `Describe*`, `List*`, `Get*`) to inventory cloud resources and IAM policies.
6. The tool performs automated simulation of privilege escalation paths or IAM permission testing (e.g., `iam:Simulate*`).
7. Adversary uses discovered credentials or modified roles to pivot into the cloud console or perform data exfiltration.

## Impact

Successful execution of these frameworks allows attackers to identify and exploit misconfigured IAM roles, escalate privileges to administrator-level access, and persist within the cloud environment. This often leads to the compromise of sensitive data, exfiltration of cloud secrets, and broader lateral movement across the organization's cloud infrastructure.

## Recommendation

1. Deploy the Sigma rules below to monitor for the launch of offensive cloud tools on sensitive endpoints.
2. Correlate alerts with known red team engagement schedules and authorized security assessment windows to minimize noise.
3. Investigate the parent process of any detected tool to determine if it was launched via manual interaction, an automated task, or an unexpected CI/CD pipeline component.
4. Perform immediate rotation of any cloud credentials found on compromised hosts identified in the alerts.
5. Review CloudTrail logs for the specific cloud principal used by the tool to identify unauthorized `iam:CreateAccessKey` or `iam:AttachUserPolicy` calls.
