---
title: Suspicious Instance Metadata Service API Requests
slug: 2026-09-imds-credential-theft
description: Attackers with initial code execution on cloud-hosted virtual machines query the Instance Metadata Service (IMDS) at 169.254.169.254 to harvest sensitive instance details and temporary security credentials for unauthorized cloud control-plane access.
date: "2026-09-18T19:08:56Z"
lastmod: "2026-09-19T13:10:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - discovery
  - imds
  - cloud-security
  - linux
  - windows
  - macos
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A common attacker pattern is gaining code execution on a Linux or Windows VM, then using curl, PowerShell, or a script dropped in a temporary directory to query 169.254.169.254 and harvest the attached role credentials for follow-on cloud access.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_suspicious_instance_metadata_service_api_request.toml
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Suspicious IMDS API Requests
    description: Detects suspicious processes or scripts querying the cloud Instance Metadata Service (IMDS) at 169.254.169.254
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy IMDS network detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Source provided logic for monitoring 169.254.169.254 traffic
  hunt_leads:
    - lead: Search for processes (curl, wget, python) communicating with 169.254.169.254 outside of authorized boot windows
      technique_id: T1552.005
      data_needed:
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Pattern described in source as common for IMDS credential harvesting
updates:
  - at: "2026-09-19T13:10:56Z"
    level: L1
    summary: OS linux; OS macos; OS windows
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_suspicious_instance_metadata_service_api_request.toml
---

Attackers frequently leverage access to cloud-hosted virtual machines to target the Instance Metadata Service (IMDS). By querying the well-known, non-routable IP address 169.254.169.254, adversaries can retrieve instance-specific metadata, such as public IP addresses, instance IDs, and - most critically - temporary IAM role credentials or managed identity tokens. This technique is often used as a post-exploitation step to escalate privileges into the cloud control plane. Defenders should monitor for unexpected network traffic directed at this endpoint from shell interpreters, scripting engines, or binaries executing from user-writable and temporary directories. The activity is distinct from legitimate bootstrap or configuration scripts, which typically execute from authorized system paths at startup.

## Attack Chain

1. Attacker gains initial code execution on a cloud virtual machine via exploit or compromised credentials.
2. Attacker performs local reconnaissance to locate configuration files or shell history (Discovery).
3. Attacker uses a common tool (e.g., curl, PowerShell) or a custom script to query the IMDS endpoint at 169.254.169.254 (Discovery/Credential Access).
4. IMDS returns sensitive metadata and temporary security credentials to the attacker process.
5. Attacker captures the returned token or credential material from the process output.
6. Attacker utilizes the harvested cloud credentials to interact with cloud APIs (e.g., S3, Secrets Manager, IAM) to exfiltrate data or persist in the cloud environment (Impact).

## Impact

Successful exploitation allows attackers to bypass host-level security boundaries and move laterally into the cloud control plane. By assuming the identity of the compromised instance's service role, attackers can gain unauthorized access to sensitive cloud storage, managed secrets, IAM policies, and other subscription resources, potentially leading to widespread data exposure or further infrastructure takeover.

## Recommendation

1. Deploy the provided Sigma rule to identify unauthorized network connections to the IMDS endpoint.
2. Baseline your environment to distinguish between legitimate bootstrap/agent activity and malicious IMDS queries originating from interactive shells or temporary directories.
3. Enforce IMDSv2 (or equivalent provider-specific hardening) to require session tokens and disable metadata access for non-essential processes.
4. Regularly rotate instance profile and managed identity credentials if suspicious IMDS query activity is detected.
