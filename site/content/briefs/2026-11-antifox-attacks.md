---
brief_id: brief-2026-11-11-antifox-attacks
event_id: brief-2026-11-11-antifox-attacks
revision: 1
activity_at: "2026-11-11T16:44:41Z"
title: AntiFox AI Pentesting Platform Used for AWS Credential Theft and Lateral Movement
slug: 2026-11-antifox-attacks
description: Threat actors are weaponizing the AntiFox agentic AI platform to automate the exploitation of internet-facing IIS servers, facilitate web shell deployment, and conduct lateral movement into AWS environments via stolen credentials.
date: "2026-11-11T16:44:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
tags:
  - ai-assisted
  - cloud-security
  - credential-theft
  - lateral-movement
vendors:
  - Microsoft
  - Amazon
products:
  - Internet Information Services
  - AWS
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The creation of an ASPX web shell by w3wp.exe, followed by command execution through the same IIS worker process, suggests compromise through the affected web application.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    subtechnique_id: T1505.003
    subtechnique_name: Web Shell
    evidence: The activity has been observed chaining together web exploitation and web shell deployment to facilitate configuration discovery.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Run PowerShell commands to locate web.config files and configuration backups, enumerate debug and error-log directories.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Read application settings and database connection strings; attempts to connect to an internal production database using a credential extracted from the application configuration.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/antifox-ai-pentesting-platform-linked.html
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Cloud Security
    - Detection Engineering
  immediate_actions:
    - action: Scan web-accessible directories on all internet-facing IIS servers for unauthorized ASPX files.
      owner: SOC
      due: 24h
      evidence: The creation of an ASPX web shell by w3wp.exe suggests compromise through the affected web application.
    - action: Audit CloudTrail logs for unusual API call volume, specifically focusing on GetSecretValue and service enumeration patterns.
      owner: Cloud Security
      due: 24h
      evidence: In at least some instances, the activity has been observed progressing beyond Secrets Manager enumeration to a successful GetSecretValue request.
  hunt_leads:
    - lead: Identify w3wp.exe spawning shell processes (cmd.exe, powershell.exe) or creating new files in the web root.
      technique_id: T1505.003
      data_needed:
        - Process creation telemetry from IIS hosts
        - File system auditing on web root directories
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The creation of an ASPX web shell by w3wp.exe, followed by command execution through the same IIS worker process, suggests compromise.
---

Arctic Wolf Labs has identified a malicious campaign leveraging AntiFox, an open-source AI-driven autonomous penetration testing platform. The attackers use AntiFox to automate post-exploitation tasks, including configuration discovery, AWS service enumeration, and secret exfiltration. The platform, available on GitHub, enables threat actors to execute multi-stage engagement workflows with minimal human intervention.

## Attack Chain

1. Initial access is achieved via an undisclosed vulnerability in an internet-facing IIS application.
2. The actor deploys an ASPX web shell using the w3wp.exe IIS worker process.
3. The agent uses the web shell to execute operating system commands to locate web.config files and configuration backups.
4. Sensitive data, including application settings and database connection strings, are read and exfiltrated to a web-accessible directory.
5. The actor attempts to connect to internal production databases using credentials extracted from the application configuration.
6. The actor leverages stolen or discovered AWS IAM identities to enumerate cloud services (e.g., S3, Secrets Manager, RDS) and exfiltrate production secrets via API calls.

## Impact

Observed impact includes the compromise of internet-facing IIS web servers, unauthorized access to application configuration files and database credentials, and confirmed exfiltration of production secrets from AWS environments. Attackers successfully leveraged AWS API calls for service enumeration and secret extraction.

## Recommendation

- Audit all internet-facing IIS servers for unauthorized ASPX files in web-accessible directories, particularly those created by the w3wp.exe process.
- Implement strict egress filtering on web servers to prevent unauthorized internal database connections and AWS API service communication.
- Review AWS IAM logs for anomalous enumeration activity (e.g., Describe*, List* operations across multiple services) followed by unauthorized GetSecretValue requests.
- Monitor GitHub repositories and developer tools for the presence of autonomous penetration testing frameworks like AntiFox, which may be repurposed by malicious actors within your environment.
