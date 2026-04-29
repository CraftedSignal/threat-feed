---
title: Maltrail IOCs Targeting Multiple Threat Actors
slug: 2026-03-maltrail-iocs
description: This brief analyzes IOCs aggregated by Maltrail on March 13, 2026, revealing network activity associated with multiple threat actors including UNC2465, SideWinder, 0ktapus, LummaC2, XWorm, PowerShell Injector, CyberStrikeAI, and others, indicating potential widespread targeting and diverse attack vectors.
date: "2026-03-13T23:00:14Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - maltrail
  - ioc
  - threat-actor
  - network-traffic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.circl.lu/doc/misp/feed-osint/63adc937-9506-463f-9d28-ec2e3ac56093.json
iocs:
  - type: domain
    value: rvtoolsup.com
  - type: ip
    value: 172.245.82.123
  - type: domain
    value: clabmadamba.pages.dev
  - type: domain
    value: hidkomas.pages.dev
  - type: domain
    value: espainaturalment.com
  - type: domain
    value: lifewithdogsstudio.com
  - type: domain
    value: dzkxxcsbrg7bwnlwwer563yuxd5pesr42dx634w5xvofm5z6qjw72ayd.onion
  - type: domain
    value: bahria-edu.workers.dev
  - type: domain
    value: cc-cvbs-sco.workers.dev
  - type: domain
    value: cms.bahria-edu.workers.dev
  - type: domain
    value: support.cc-cvbs-sco.workers.dev
  - type: domain
    value: com-e-visa.online
  - type: domain
    value: visa.nadra.gov.pk.com-e-visa.online
  - type: domain
    value: atocalculation.com
  - type: domain
    value: geo-foundation.vg
  - type: domain
    value: microservice.gl
  - type: domain
    value: ros-tele.com
  - type: domain
    value: rostov-uga.com
  - type: domain
    value: ug-network.com
  - type: ip
    value: 186.169.43.64
  - type: domain
    value: sostener2025.duckdns.org
  - type: domain
    value: teste258588.duckdns.org
  - type: ip
    value: 89.124.77.234
  - type: domain
    value: mastluner.club
  - type: domain
    value: orkneygateway.com
  - type: domain
    value: tel.orkneygateway.com
  - type: ip
    value: 115.159.42.173
  - type: ip
    value: 117.72.74.158
  - type: ip
    value: 172.86.114.64
  - type: ip
    value: 43.130.44.204
  - type: ip
    value: 45.192.103.176
  - type: ip
    value: 51.195.25.206
ioc_counts:
  domain: 23
  ip: 9
rules:
  - title: Detect Connections to DuckDNS Domains
    description: Detects connections to domains hosted on duckdns.org, often used for dynamic DNS by malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connections to Known Malicious IPs
    description: Detects connections to a list of known malicious IP addresses.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 13, 2026, Maltrail, an open-source malicious traffic detection system, identified a series of IOCs associated with various threat actors and campaigns. This intelligence brief focuses on several notable clusters of activity, including those linked to APT groups like UNC2465 and SideWinder, as well as malware families such as LummaC2, XWorm, and PowerShell Injector. The identified IOCs consist primarily of domains and IP addresses used for command and control (C2) or other malicious purposes. This broad spectrum of detected activity suggests a landscape where multiple threat actors are actively probing or exploiting vulnerabilities across different sectors, posing a risk of data theft, ransomware deployment, or persistent compromise. Defenders need to prioritize detections covering these diverse attack vectors.

## Attack Chain

1.  **Initial Access:** While the specific initial access vectors are not detailed in the provided source, several of the identified threat actors, such as SideWinder and 0ktapus, are known to utilize phishing campaigns.
2.  **Malware Delivery/Execution:** The threat actors deliver their respective payloads via compromised websites or direct execution using techniques such as PowerShell injection.
3.  **Command and Control:** The malware establishes a connection to a C2 server using domains such as `rvtoolsup.com` (UNC2465), `geo-foundation.vg` (LummaC2), or IP addresses like `172.245.82.123` (SuperShell_C2).
4.  **Persistence:** Some malware families, like XWorm, might use persistence mechanisms to ensure continued access to the compromised system.
5.  **Data Exfiltration:** LummaC2 is known for stealing sensitive information such as credentials and cookies from web browsers.
6.  **Lateral Movement:** Depending on the attacker's objective, lateral movement may occur within the compromised network to reach valuable assets.
7.  **Final Objective:** The ultimate goal varies depending on the threat actor. It may include data theft, espionage, or disruption of services. For LokiLocker the goal is ransomware deployment.
8.  **Impact:** The final impact includes data encryption from ransomware, sensitive data exfiltration, or system compromise, depending on the threat actor's objectives.

## Impact

The observed network activity associated with these threat actors indicates a potential for widespread compromise. While the exact number of victims remains unknown, the diversity of actors suggests that multiple sectors could be affected. Successful attacks could result in data breaches, financial losses, reputational damage, and disruption of services. Specifically, ransomware attacks (e.g., LokiLocker) could lead to significant operational downtime and financial demands for data recovery. Credential theft (e.g., LummaC2, 0ktapus) could enable further attacks and compromise sensitive systems.

## Recommendation

*   Monitor network traffic for connections to the IOCs listed in this brief, specifically the domains associated with LummaC2 (e.g., `geo-foundation.vg`, `microservice.gl`, `ros-tele.com`, `rostov-uga.com`, `ug-network.com`) to detect potential C2 communications.
*   Implement the Sigma rule "Detect Connections to DuckDNS Domains" to identify potential XWorm infections using the domains `sostener2025.duckdns.org` and `teste258588.duckdns.org`.
*   Deploy the Sigma rule "Detect Connections to Known Malicious IPs" and update it with the IP addresses `172.245.82.123` (SuperShell_C2), `186.169.43.64` (XWorm), `89.124.77.234` (PowerShell_Injector), and the CyberStrikeAI IPs (`115.159.42.173`, `117.72.74.158`, `172.86.114.64`, `43.130.44.204`, `45.192.103.176`, `51.195.25.206`) to detect potential malicious network connections.
