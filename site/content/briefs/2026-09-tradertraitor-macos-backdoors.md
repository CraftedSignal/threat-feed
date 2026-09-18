---
title: TraderTraitor Campaign Targeting DevOps Engineers via Weaponized Terraform Repositories
slug: 2026-09-tradertraitor-macos-backdoors
description: North Korean threat actor TraderTraitor is using fake job interview lures on GitHub containing weaponized Terraform lock files to deliver macOS backdoors to DevOps engineers, facilitating cloud credential theft.
date: "2026-09-18T19:45:57Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TraderTraitor
tags:
  - macos
  - tradertraitor
  - supply-chain
  - social-engineering
  - cloud-security
  - devops
vendors:
  - HashiCorp
products:
  - Terraform
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Each campaign related to this wave of activity uses social engineering via fake job interview lures.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: After an employee installed a weaponized interview coding project on their company workstation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: TraderTraitor used the backdoors to collect API keys from the organization and to escalate privileges.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: SystemUpdate => technicais, iSync => hubpage, Telegram at 05:00:58.
    confidence_band: high
iocs:
  - type: domain
    value: registry.hashicorp-aws.com
  - type: domain
    value: registry.hashicorp-aws.io
  - type: domain
    value: registry.hashicorp-terraform.io
  - type: ip
    value: 176.97.114.232
  - type: ip
    value: 45.11.59.140
ioc_counts:
  domain: 3
  ip: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified C2 IPs and malicious registry domains on perimeter firewalls and DNS resolvers.
      owner: SOC
      due: 24h
      evidence: IOC list provided in the brief.
  hunt_leads:
    - lead: Search for .terraform.lock.hcl files containing non-HashiCorp registry domains.
      technique_id: T1204.002
      data_needed:
        - EDR file integrity or scan results
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Weaponized .terraform.lock.hcl file using a typosquatted provider domain.
  mitigation_plan:
    - priority: immediate
      action: Educate developers on verifying Terraform lock files and avoiding untrusted repository clones.
      owner: IT Operations
      addresses: T1566.002
      evidence: Source material on social engineering via job lures.
---

The North Korean state-sponsored threat actor TraderTraitor (also known as UNC4899, PUKCHONG, and Jade Sleet) is actively conducting social engineering campaigns targeting DevOps and cryptocurrency engineers. The group creates fake job interview coding projects on GitHub, specifically using names like 'Northwind-IAC' and 'novacart-interview', to entice targets into downloading and running infrastructure-as-code projects. 

The malicious mechanism relies on weaponized '.terraform.lock.hcl' files. By configuring these files to point to attacker-controlled domains - such as registry.hashicorp-aws[.]com - the threat actor forces the execution of `terraform init` to download and run arbitrary malicious provider modules. Once the victim executes the code on their macOS workstation, the FLATROOF (macOS.Gaslight) and ROOFDECK backdoors are deployed. These backdoors enable the attackers to establish persistence, collect sensitive cloud API keys (AWS, GCP), and perform lateral movement. The campaign targets individuals in the IT services sector regardless of cryptocurrency ties, demonstrating a broad operational scope for gaining unauthorized access to production cloud environments.

## Attack Chain

1. Attacker establishes contact with a target developer via social engineering through fake job interview lures on GitHub.
2. Target downloads a weaponized coding project repository containing a modified '.terraform.lock.hcl' file.
3. Victim executes `terraform init` within the project directory on their macOS workstation.
4. Terraform client reaches out to an attacker-controlled registry domain (e.g., registry.hashicorp-terraform[.]io) to download the provider.
5. Malicious provider code is executed, deploying FLATROOF and ROOFDECK backdoors onto the local macOS system.
6. Backdoors perform a Gatekeeper bypass by executing `xattr -rd com.apple.quarantine` and changing file permissions (`chmod +x`).
7. Implants establish persistent C2 communication via hardcoded IPs and transmit stolen cloud credentials to the threat actor.
8. Attacker uses stolen credentials to escalate privileges and access cloud infrastructure (AWS/GCP).

## Impact

Successful compromise results in full access to the victim's local developer workstation, theft of cloud environment credentials (AWS, GCP, OVH), and potential lateral movement into the organization's cloud production environments. This threat impacts DevOps teams and software engineers, potentially leading to widespread unauthorized access to private corporate infrastructure, data exfiltration, or further supply chain compromises.

## Recommendation

* Audit all `terraform init` activity and restrict egress traffic for developer workstations to verified Terraform registry domains (registry.terraform.io) only.
* Block the malicious provider registry domains listed in the IOC table at the DNS resolver level.
* Deploy Sigma rules to detect unauthorized execution of `terraform` commands from non-standard directories or unusual network destinations.
* Monitor macOS endpoints for suspicious process executions involving `zsh` spawning shell commands that include `xattr` or `chmod +x` on binaries located in application or temporary directories.
* Implement security awareness training regarding the risks of running third-party infrastructure-as-code project repositories from untrusted sources.
