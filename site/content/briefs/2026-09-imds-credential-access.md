---
title: Detection of Unauthorized Cloud Instance Metadata Service Access
slug: 2026-09-imds-credential-access
description: Attackers exploit cloud instance metadata service (IMDS) endpoints by using command-line tools to exfiltrate temporary security credentials and sensitive configuration data, facilitating unauthorized access to cloud resources.
date: "2026-09-18T19:08:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - cloud
  - discovery
  - imds
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This rule identifies various tools/scripts performing command line execution attempting to access the cloud service provider's instance metadata service (IMDS) API endpoint.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: The rule detects activity identifying system information through metadata service queries.
    confidence_band: high
iocs:
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: metadata.google.internal
ioc_counts:
  domain: 1
  ip: 1
rules:
  - title: Detect Suspicious Instance Metadata Service (IMDS) Access
    description: Detects command-line execution attempting to access IMDS API endpoints for credential or token retrieval
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify command-line access to IMDS endpoints
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for command lines containing 169.254.169.254 or cloud-specific metadata paths
      technique_id: T1552.005
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Require IMDSv2 and restrict metadata access to authorized service accounts
      owner: Cloud Engineering
      addresses: T1552.005
---

This threat involves the exploitation of the cloud Instance Metadata Service (IMDS) by adversaries to perform credential theft and environment discovery. By gaining command execution on a cloud-resident virtual machine, attackers use common utilities such as curl, wget, or native shell commands to query the IMDS endpoint. This technique allows attackers to retrieve highly sensitive information, including instance identity, public IP addresses, and, most critically, temporary IAM role credentials or managed identity tokens. Once acquired, these credentials are used to authenticate to cloud APIs - such as storage buckets, secrets managers, or subscription management services - without the need for long-term passwords. This activity is often a precursor to broader lateral movement and privilege escalation within a cloud environment. Monitoring for command-line access to these specific metadata URIs is essential for detecting post-exploitation discovery and exfiltration phases.

## Attack Chain

1. Attacker gains initial access to a cloud-based virtual machine via web application exploitation or remote command execution.
2. Attacker performs internal reconnaissance to identify the environment as a cloud instance and locates the IMDS address (e.g., 169.254.169.254).
3. Attacker identifies the appropriate API path for credential or token retrieval, such as `/latest/meta-data/iam/security-credentials/` or equivalent cloud-specific token endpoints.
4. Attacker invokes common system utilities or interpreters like `curl`, `wget`, `powershell.exe`, or `python` to query the identified metadata path.
5. The metadata service returns the temporary security credentials or OAuth access tokens to the attacker-controlled process.
6. Attacker exfiltrates these credentials from the local host to an external command-and-control server or uses them immediately to access cloud services.
7. Attacker utilizes the stolen credentials to interact with cloud management APIs, storage, or secrets providers to achieve their final objective (exfiltration, sabotage, or persistence).

## Impact

Successful exploitation leads to the loss of workload identity, allowing attackers to impersonate the instance's service role. This can result in unauthorized access to sensitive cloud data, modification of infrastructure configurations, and persistent access to the cloud environment, potentially impacting large-scale deployments across sectors utilizing cloud infrastructure.

## Recommendation

1. Deploy the Sigma rules provided in this brief to detect suspicious command-line execution targeting IMDS endpoints.
2. Require IMDSv2 or similar protections that mandate session-oriented authentication to mitigate unauthorized metadata access.
3. Review IAM roles and managed identities attached to virtual machines to ensure the principle of least privilege is applied, limiting the impact if credentials are stolen.
4. Block outbound connections from production workloads to the IMDS endpoint for any process that does not have a documented, legitimate business requirement.
5. Configure alerting for the use of cloud CLI tools or SDKs using credentials retrieved from the metadata service in unexpected geographic locations.
