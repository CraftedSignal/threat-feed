---
title: Detection of Multi-Cloud CLI Token and Credential Harvesting
slug: 2026-09-multi-cloud-cli-token-harvesting
description: Threat actors harvest cloud and container platform authentication tokens by abusing legitimate CLI utilities to output secrets to standard streams, which can be detected via anomalous multi-provider access patterns.
date: "2026-09-18T19:08:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - cloud-security
  - supply-chain
vendors:
  - Google
  - Microsoft
  - Amazon
  - GitHub
  - DigitalOcean
  - Oracle
  - Cloud Native Computing Foundation
products:
  - Google Cloud SDK
  - Azure CLI
  - AWS CLI
  - GitHub CLI
  - Kubernetes
  - DigitalOcean CLI
  - Oracle Cloud Infrastructure CLI
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Threat actors may attempt to harvest cloud and container platform credentials by executing CLI commands that output authentication tokens or secrets to standard output or logs.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The detection logic identifies anomalous behavior where a user or host accesses tokens for multiple cloud providers, which is often indicative of automated credential theft.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1528/
  - https://attack.mitre.org/techniques/T1552/
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security Team
  immediate_actions:
    - action: Deploy detection rule for multi-provider CLI token access patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific CLI command line patterns associated with token exfiltration.
  hunt_leads:
    - lead: Search endpoint logs for interactive shell usage alongside CLI authentication commands
      technique_id: T1528
      data_needed:
        - Process creation events (Event ID 1 / Sysmon)
        - Command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source highlights process telemetry for shells and major cloud CLIs as a primary detection data source.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict service-account token export permissions in CI/CD pipelines
      owner: Cloud Security Team
      addresses: T1528
      evidence: Source notes that automation and CI runners may legitimately print tokens, implying this is a common exposure point.
  gaps:
    - Lack of native auditing for token usage post-exfiltration across all providers
---

Adversaries frequently target cloud-native environments by exploiting legitimate CLI tools to exfiltrate session tokens and credentials. By executing commands such as 'az account get-access-token', 'gcloud auth print-access-token', or 'kubectl get secret', attackers can capture sensitive authentication material from a host's local session. When these actions target multiple cloud providers (AWS, GCP, Azure, GitHub, OCI, or DigitalOcean) within a short window, it strongly indicates malicious reconnaissance or automated credential harvesting rather than standard administrative tasks. This activity is critical to identify, as printed tokens can be used to pivot deeper into the cloud infrastructure, bypass MFA, or maintain persistence in the target environment. Detection engineers should baseline existing CI/CD pipelines to distinguish legitimate service-principal activity from interactive or unauthorized shell-based token access.

## Attack Chain

1. Initial access is established on the endpoint via remote shell, compromised RMM, or scheduled tasks.
2. The attacker identifies the presence of cloud CLI tools (e.g., gcloud, az, aws, gh, kubectl) in the PATH.
3. The attacker executes authentication-related commands within an interactive or scripted shell to output bearer tokens to stdout.
4. The process is repeated for different cloud provider CLI tools installed on the same host.
5. The attacker captures the printed output (tokens, identity strings, or secrets) using redirection or terminal monitoring.
6. The captured tokens are exported off-host for use in secondary authentication.
7. The final objective is unauthorized cloud API access for data exfiltration, lateral movement, or environment takeover.

## Impact

Successful harvesting of cloud CLI tokens allows unauthorized actors to bypass local identity controls and gain persistent access to cloud resources. This can lead to massive data breaches, resource hijacking for cryptomining, or the disabling of security services within the target cloud environment. Affected sectors include any organization relying on hybrid or multi-cloud infrastructure and automated CI/CD processes.

## Recommendation

Prioritize monitoring for CLI-based token access on all developer and jump-host systems.
- Implement the detection logic below to identify when users or systems interact with multiple cloud provider CLI tools in a 5-minute window.
- Audit existing CI/CD runners and deployment scripts to establish an allowlist of service identities.
- Force revocation and rotation of any credentials printed to stdout if unauthorized access is confirmed.
- Utilize provider-console revocation (e.g., Azure Entra ID or GCP IAM) rather than relying on local CLI logout commands, as local logout does not invalidate tokens already captured by the attacker.
