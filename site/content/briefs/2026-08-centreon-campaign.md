---
title: Historical Campaign Targeting Centreon IT Monitoring Software
slug: 2026-08-centreon-campaign
description: Between 2017 and 2020, threat actors targeted Centreon environments at IT service providers by deploying the P.A.S. webshell and the Exaramel backdoor.
date: "2026-08-29T19:11:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - centreon
  - webshell
  - backdoor
  - persistence
  - monitoring
vendors:
  - Centreon
products:
  - Centreon (monitoring software)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.003
    technique_name: 'Scheduled Task/Job: Cron'
    evidence: its persistence is ensured via a scheduled task (Cron).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: On the compromised systems, the webshell P.A.S. (alias Fobushell) is deployed in the Centreon web folder.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: 'Note: Exaramel communicates with its command and control servers via HTTPS.'
    confidence_band: high
references:
  - https://www.circl.lu/doc/misp/feed-osint/60118dab-1ab8-40b2-b02b-b6f80aba047c.json
  - https://wws.cert-ist.com/private/fr/IocAttack_details?format=html&objectType=ATK&ref=CERT-IST/ATK-2016-066
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit server directories for unexpected files named .applock, .applocktx, or configtx.json
      owner: SOC
      due: 48h
      evidence: Artifacts dropped in source
  hunt_leads:
    - lead: Search for unknown scripts within Centreon web directories
      technique_id: T1505.003
      data_needed:
        - File system auditing logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: webshell P.A.S. deployed in the Centreon web folder
  mitigation_plan:
    - priority: short_term
      action: Enforce strict file permissions in Centreon web directories and implement egress filtering
      owner: IT Operations
      addresses: Webshell and C2 communication
      evidence: Anonymization infrastructure usage
---

Between 2017 and 2020, threat actors targeted entities using Centreon IT monitoring software, with a focus on web hosting providers and IT service organizations. The campaign involved unauthorized access to Centreon servers, leading to the deployment of the P.A.S. (Fobushell) webshell within the Centreon web directory. This webshell served as the primary entry point for manual interaction and follow-on malicious activity. In several identified cases, the actors deployed the Exaramel backdoor, a malware written in the Go programming language, to further strengthen their control over the compromised systems. Exaramel achieved persistence through scheduled cron tasks and communicated with external command-and-control (C2) infrastructure via HTTPS. The attackers utilized anonymization services, including Tor and commercial VPNs, to obfuscate their connection to the deployed webshells. While the report mentions similarities in TTPs to the Sandworm intrusion set, the French national cybersecurity agency (ANSSI) noted that these attributions remain inconclusive due to the limited nature of the shared operational elements.

## Attack Chain

1. Initial exploitation of unknown vulnerabilities or weaknesses in the target Centreon installation.
2. Unauthorized file upload of the P.A.S. (Fobushell) webshell into the Centreon web directory.
3. Authentication to the webshell using a predefined password to execute arbitrary commands.
4. Deployment of the Exaramel backdoor (Go-based) into the Centreon directory.
5. Establishment of persistence for the Exaramel backdoor using a Linux Cron scheduled task.
6. Configuration of Exaramel via local files (e.g., configtx.json) and creation of temporary socket files in /tmp/ for communication.
7. Exfiltration or command execution via Exaramel communicating with C2 servers over HTTPS.
8. Use of Tor or VPN services by operators to obscure management of the webshell and C2 channels.

## Impact

The campaign resulted in the compromise of several French entities, particularly IT service providers and web hosting firms. Successful exploitation allowed attackers to maintain persistent, long-term access to critical infrastructure monitoring systems, posing significant risks of data exfiltration, lateral movement within the provider's network, and potential disruption of monitoring services for downstream clients.

## Recommendation

Prioritize the identification and removal of unauthorized files within the Centreon directory structure and monitor for suspicious scheduled tasks.

- Deploy file integrity monitoring (FIM) on the Centreon web directory to detect unauthorized additions of PHP or binary files.
- Audit existing cron jobs on all Centreon monitoring servers for unexpected execution paths.
- Implement network egress filtering to restrict unauthorized HTTPS traffic from monitoring servers to known Tor exit nodes or unapproved VPN endpoints.
- Scan the /tmp/ directory for artifacts associated with Exaramel, such as files named .applock or .applocktx.
