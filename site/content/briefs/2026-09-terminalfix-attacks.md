---
title: TerminalFix Attacks Deploying Reverse Tunnels on Windows
slug: 2026-09-terminalfix-attacks
description: Microsoft warns of a campaign known as TerminalFix that utilizes malicious scripts to establish reverse tunnels on Windows systems to maintain persistent remote access.
date: "2026-09-09T06:45:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - command-and-control
  - windows
  - terminalfix
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Microsoft warns of TerminalFix attacks deploying reverse tunnels.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Attacks deploy reverse tunnels on compromised Windows systems.
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/microsoft-warns-of-terminalfix-attacks-deploying-reverse-tunnels
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review endpoint logs for anomalous script execution patterns associated with reverse tunnel software (e.g., chiseled, ngrok, or similar tools).
      owner: SOC
      due: 24h
      evidence: Threat actors deploy reverse tunnels on compromised Windows systems.
  hunt_leads:
    - lead: Identification of unexpected reverse proxy or tunneling binaries running on endpoint assets.
      technique_id: T1090
      data_needed:
        - Process creation logs with full command line arguments
        - Network connection logs for unusual outbound traffic
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacks deploy reverse tunnels on compromised Windows systems.
  mitigation_plan:
    - priority: medium_term
      action: Restrict the execution of unauthorized scripting languages and unauthorized binary execution via AppLocker or WDAC.
      owner: IT Operations
      addresses: Technique T1059.003
      evidence: Use of malicious scripts to deploy reverse tunnels.
---

Microsoft has issued a warning regarding a campaign dubbed TerminalFix, which targets Windows environments to establish long-term persistence and unauthorized remote access. Attackers leverage specific malicious scripts designed to execute within the victim's environment, subsequently deploying reverse tunneling mechanisms. These tunnels allow the threat actors to bypass standard perimeter security controls, enabling them to maintain connectivity to the internal network from external command-and-control infrastructure. The campaign focuses on compromising endpoint integrity to facilitate deeper penetration into the target environment. Given the nature of the persistent access established via reverse tunneling, this threat represents a significant risk for lateral movement, data exfiltration, and the deployment of secondary payloads. Defenders should focus on identifying unauthorized tunnel creation and the execution of suspicious scripts that deviate from established administrative baselines.

## Impact

Successful execution of TerminalFix allows threat actors to bypass network perimeter defenses, maintaining stable, long-term remote access to compromised Windows hosts. This access is typically used as a springboard for further malicious activities, including credential harvesting, lateral movement through the internal network, and the potential exfiltration of sensitive organizational data. If left unmitigated, victims face a heightened risk of full domain compromise and follow-on attacks, such as ransomware or targeted intellectual property theft.

## Recommendation

Prioritize monitoring for unauthorized reverse tunneling activity on Windows hosts. Enable process-creation logging to capture script execution associated with the TerminalFix toolkit.
