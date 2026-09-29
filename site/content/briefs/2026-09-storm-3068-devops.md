---
title: Storm-3068 Exploitation of Azure DevOps for Cloud Infrastructure Access
slug: 2026-09-storm-3068-devops
description: Storm-3068 exploited a compromised identity via self-service password reset to manipulate CI/CD pipelines, harvest Kubernetes credentials, and deploy remote management tools for persistent cloud access.
date: "2026-09-29T19:16:53Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-3068
tags:
  - cloud-security
  - devops
  - identity
  - persistence
vendors:
  - Microsoft
  - Atera
products:
  - Azure DevOps
  - Kubernetes
  - Atera
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The intrusion began with Storm-3068 gaining access to a user account through a self-service password reset process
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The threat actor modified development pipelines to collect Kubernetes credentials and expand access into cloud infrastructure.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: The threat actor modified pipeline scripts to install the Atera remote management agent and download the Chisel tunneling utility.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: executed multiple jobs intended to collect kubeconfig files containing cluster connection details and authentication information.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
    - DevSecOps
  immediate_actions:
    - action: Review and restrict access to self-service password reset portals for high-privilege accounts
      owner: Identity Team
      due: 24h
      evidence: Strengthening protection for privileged accounts by limiting exposure to self-service password reset workflows
    - action: Audit CI/CD pipeline definitions for unauthorized modifications or embedded remote management scripts
      owner: DevSecOps
      due: 48h
      evidence: modified pipeline scripts to install the Atera remote management agent
  hunt_leads:
    - lead: Search Azure DevOps audit logs for unauthorized pipeline modifications or creation of new service connections
      technique_id: T1059
      data_needed:
        - Azure DevOps audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The threat actor modified development pipelines to collect Kubernetes credentials
  mitigation_plan:
    - priority: immediate
      action: Enable phishing-resistant MFA for all users interacting with CI/CD and cloud management consoles
      owner: Identity Team
      addresses: Account hijacking and MFA registration
      evidence: requiring phishing-resistant multifactor authentication
---

Microsoft DART investigators documented Storm-3068 activity where a single compromised identity served as the initial access vector into a target's Azure DevOps and production environments. The actor utilized a self-service password reset process to hijack the account, subsequently registering their own MFA methods to maintain persistence. Once inside, the actor leveraged administrative tools and automated scripts to enumerate Azure DevOps repositories, projects, and pipeline definitions. By identifying trusted deployment paths, Storm-3068 modified CI/CD pipelines to execute malicious code, including the deployment of Atera remote management agents and the Chisel tunneling utility. The objective was to harvest Kubernetes kubeconfig files and establish a reverse tunnel to external infrastructure, providing the actor with broad, persistent access to the organization's cloud environment. This incident demonstrates the risk associated with tightly integrated identity and development pipelines.

## Attack Chain

1. Initial access is gained by the actor through a self-service password reset process, hijacking a legitimate user account.
2. Persistence is established by the actor registering their own MFA/authentication methods for the compromised account.
3. The actor uses the compromised account to enumerate Azure DevOps repositories, deployment environments, and pipeline configurations.
4. Malicious scripts are injected into legitimate CI/CD pipelines, leveraging the identity's permissions to interact with connected cloud services.
5. The compromised pipeline is used to deploy a kube agent and execute commands to harvest kubeconfig files and cluster authentication details.
6. The pipeline script is further modified to download and execute the Atera remote management agent for persistent remote access.
7. The Chisel utility is executed via pipeline scripts to establish a reverse tunnel to an actor-controlled IP, exposing the Kubernetes API server.
8. Stolen kubeconfig files are exfiltrated and uploaded to a repository to facilitate subsequent direct access to targeted Kubernetes clusters.

## Impact

The breach resulted in unauthorized access to over 50 cloud resources, including sensitive Kubernetes clusters. By moving from a single user identity to full pipeline and cloud infrastructure control, the actor gained the capability to manage production environments, potentially exposing or altering data and infrastructure configuration at scale.

## Recommendation

Prioritize hardening identity and DevOps workflows by auditing access and pipeline configurations.
* Implement phishing-resistant MFA for all privileged and standard accounts to prevent identity hijacking via reset processes.
* Enforce strict branch protection and code review requirements to prevent unauthorized modifications to pipeline definition files.
* Apply principle of least privilege to pipeline service connections to ensure they only possess permissions necessary for their specific deployment task.
* Establish monitoring for anomalous activity within Azure DevOps audit logs, specifically focusing on pipeline modifications and unusual user additions to administrative roles.
