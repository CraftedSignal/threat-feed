---
title: Slim Spider Targets Brazilian Financial Institutions via Cloud Infrastructure
slug: 2026-09-slim-spider
description: Slim Spider is a financially motivated actor targeting Brazilian financial organizations by stealing cloud credentials and manipulating DevOps pipelines to gain unauthorized access to digital asset custody systems and payment infrastructure.
date: "2026-09-08T16:48:26Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Slim Spider
tags:
  - financial-crime
  - cloud-security
  - devops
  - credential-theft
  - kubernetes
vendors:
  - Microsoft
products:
  - Azure DevOps
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Slim Spider has been observed ... likely using compromised credentials, to run malicious pipelines that deployed additional implants.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The threat actor enumerated all available secrets stored in the cloud credential manager.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Bash'
    evidence: As part of the attack, the e-crime group is said to have developed custom Bash scripts that query the cloud instance metadata.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The adversary ... developed custom Bash scripts that query the cloud instance metadata to steal temporary cloud credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: deploying backdoors mimicking infrastructure-related binaries to blend with legitimate tooling.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/slim-spider-steals-crypto-custody.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Audit Azure DevOps pipelines for anomalous deployment activity.
      owner: DevOps/SOC
      due: 24h
      evidence: Actor compromised Azure DevOps pipelines to deploy implants.
  hunt_leads:
    - lead: Identification of unusual socket connections from containerized workloads to cloud metadata services.
      technique_id: T1552
      data_needed:
        - Network logs and container logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Bash scripts query cloud metadata via socket connections.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to IMDS endpoints for container workloads using network policies.
      owner: Cloud Engineering
      addresses: Credential theft via cloud metadata
      evidence: Actor targets cloud instance metadata.
---

Slim Spider is a newly identified, Brazil-based threat actor active since at least March 2026, focusing on financial institutions and digital asset platforms. The actor demonstrates deep operational knowledge of Brazilian financial infrastructure, specifically targeting the Pix instant payment system. Their methodology involves sophisticated cloud-native attacks, moving away from traditional retail banking fraud toward direct intrusion into core financial switches. The group employs custom Bash scripts, Go-based backdoors (MikeDor), and automated tooling to enumerate cloud environments, steal temporary credentials from metadata services, and harvest secrets from credential managers. They further expand their reach by compromising Azure DevOps pipelines to deploy malicious implants - such as those impersonating the Sistema de Pagamentos Instantâneos (SPI) - into Kubernetes clusters. These actions are supported by custom reconnaissance and transaction-focused panels that categorize financial endpoints and facilitate fraudulent payments.

## Attack Chain

1. Initial access is established via compromised credentials to gain entry into the target organization's cloud and DevOps environment.
2. The actor performs cloud environment discovery and enumerates secrets stored within the cloud credential manager.
3. Custom Bash scripts are deployed to query cloud instance metadata and exfiltrate temporary credentials over socket connections.
4. The actor uses the 'sed' command to modify and repurpose scripts for digital asset secret extraction.
5. Attacker deploys malicious pipelines within Azure DevOps to distribute implants across managed Kubernetes clusters.
6. Backdoors mimicking infrastructure binaries are deployed to nodes to maintain persistence and blend with legitimate tooling.
7. The actor utilizes the Foundry 'cast' component to derive Ethereum wallet addresses from stolen private keys.
8. Final objective is achieved by initiating fraudulent bulk Pix payments via the compromised financial infrastructure.

## Impact

Slim Spider's activities target high-value digital asset custody credentials, which can lead to catastrophic financial loss through the unauthorized transfer of cryptocurrency and fiat currency. By specifically compromising the Pix instant payment infrastructure, the actor gains the ability to execute unauthorized bulk transactions, representing a significant shift from retail banking fraud to direct financial platform exploitation within Brazil.

## Recommendation

Prioritize monitoring of cloud and CI/CD environments for suspicious credential access and unauthorized pipeline executions.
- Audit and restrict access to cloud instance metadata services, particularly for containers where such access is not required.
- Implement strict monitoring of Azure DevOps pipeline configurations for unauthorized modifications or external source integrations.
- Monitor Kubernetes cluster logs for the deployment of unexpected container images or binaries mimicking core infrastructure components.
- Enforce strict identity and access management controls for cloud-native secret management services to prevent bulk secret extraction.
