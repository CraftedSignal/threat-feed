---
title: Breeze Comet Targeting Brazilian Financial Systems
slug: 2026-09-breeze-comet
description: Breeze Comet is a financially motivated actor targeting Brazilian payment systems via social engineering, web shell deployment, and custom routing malware to execute fraudulent financial transactions.
date: "2026-09-01T18:11:12Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Breeze Comet
tags:
  - financial-fraud
  - malware
  - lateral-movement
vendors:
  - Red Hat
products:
  - JBoss AS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Initial access to financial entities and companies offering financial services is accomplished via password spraying and voice calls
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: the threat actor executes PowerShell commands to disable Windows Defender's real-time monitoring on the compromised hosts.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: KICKPLATE ... is used to deliver secondary payloads and runs commands to control SOCKS5 tunnelers
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/breeze-comet-executes-hundreds-of.html
iocs:
  - type: domain
    value: dontpad.com
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Monitor outbound traffic to dontpad.com for potential secret exfiltration
      owner: SOC
      due: 24h
      evidence: Actor exfiltrates cloud secrets to dontpad.com
  hunt_leads:
    - lead: Identification of unauthorized RDP sessions and SMB file share execution
      technique_id: T1021
      data_needed:
        - Sysmon Event ID 3 (Network connection)
        - Windows Event ID 4624 (Logon)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Moving laterally by initiating unauthorized Remote Desktop Protocol (RDP) sessions and executing commands via SMB network file shares.
  mitigation_plan:
    - priority: immediate
      action: Patch and harden all internet-facing JBoss AS instances
      owner: IT Operations
      addresses: JBoss AS web shell vulnerability
      evidence: Alternatively, the group has targeted vulnerable JBoss AS servers to deploy web shells
---

Breeze Comet (formerly tracked as UNC5669) is a financially motivated threat actor that has been targeting Brazilian financial services, retail, and e-commerce organizations since 2024. The group specializes in gaining unauthorized access to internal payment systems, including Pix, STR, and Boleto, to conduct fraudulent transfers. By leveraging a custom malware suite and LLM-assisted development, they maintain persistent access to core financial API infrastructure. Their operation requires compromising mTLS credentials and Active Directory environments to manipulate transactional flows. The group's toolkit includes backdoors such as LIGHTPAINT, MILDFROST, KICKPLATE, and BOATBEAM, alongside the COBALTSPIN routing malware. The actor's capability to move laterally through boundary firewalls and their focus on core payment switches represents a significant escalation in regional cybercrime maturity.

## Attack Chain

1. Initial access via password spraying or social engineering (voice calls/WhatsApp) to trick users into installing RMM tools like AnyDesk.
2. Exploitation of vulnerable JBoss AS servers to upload web shells for secondary payload delivery.
3. Internal reconnaissance using tools such as ADRecon, ADVipscan, and the custom REALBREEZE LDAP brute-forcing utility.
4. Lateral movement initiated via unauthorized RDP sessions and execution of commands via SMB network shares.
5. Deployment of the Rust-based COBALTSPIN malware to establish a reverse SOCKS5 proxy over WebSocket connections for secure C2 communication.
6. Persistence establishment using malicious Kubernetes pods, SoftEther VPN, or custom backdoors like KICKPLATE (impersonating Windows Update Health Tools).
7. Execution of fraudulent transactions using compromised mTLS credentials and privileged access to financial APIs.
8. Anti-forensics activity involving clearing event logs and deleting temporary directories.

## Impact

Breeze Comet has successfully conducted heists of assets worth tens of thousands of U.S. dollars. By directly targeting core financial infrastructure and payment switches, the actor poses a systemic risk to the operational integrity of Brazilian payment systems. The compromise of privileged financial API access allows for the execution of large-scale fraudulent transactions, which can result in significant financial loss, regulatory penalties, and reputational damage to affected fintech and banking entities.

## Recommendation

* Deploy detection for COBALTSPIN network patterns (reverse SOCKS5 proxies over WebSockets) at the network egress.
* Audit and restrict administrative access to internal payment APIs and mTLS credentials, ensuring robust monitoring of authenticated transactional orders.
* Implement strict control over the use of RMM tools like AnyDesk; block associated outbound connections if not explicitly required by business functions.
* Monitor for suspicious use of LDAP/Active Directory enumeration tools (ADRecon, ADVipscan) within the corporate environment.
* Harden JBoss AS servers against web shell deployment and maintain rigorous patching cycles for all internet-facing infrastructure.
