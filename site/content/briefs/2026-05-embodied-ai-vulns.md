---
title: Vulnerabilities in Unitree Embodied AI Systems
slug: 2026-05-embodied-ai-vulns
description: Commercially available Unitree robots are susceptible to multiple vulnerabilities, including hardcoded keys and command injection, allowing attackers to gain root-level access, exfiltrate data, and potentially create physical botnets.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - embodied-ai
  - robot
  - iot
  - vulnerability
  - data-exfiltration
vendors:
  - Unitree
  - BMW
  - GXO
  - Agility Robotics
  - Sellafield
products:
  - Go1
  - Go2
  - B2
  - G1
  - R1
  - H1
  - Figure 02
  - CloudSail service
  - X3 vehicles
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2025-2894
    cvss: 6.6
    epss: 0.00212
references:
  - https://www.recordedfuture.com/research/hacking-embodied-ai
  - https://nvd.nist.gov/vuln/detail/CVE-2025-2894
  - https://www.axios.com/2025/04/01/threat-spotlight-backdoor-in-chinese-robots-future-of-cybersecurity
  - https://arxiv.org/pdf/2509.14139
  - https://github.com/Bin4ry/UniPwn
  - https://spectrum.ieee.org/unitree-robot-exploit
  - https://medium.com/@creed_1732/the-unitree-g1-security-crisis-explains-how-a-humanoid-robot-became-a-spy-and-cyber-weapon-439180135ba1
  - https://www.yicaiglobal.com/news/chinese-cybersecurity-expert-hacks-control-system-of-unitrees-humanoid-robot-in-one-minute
  - https://interestingengineering.com/ai-robotics/security-flaw-could-allow-hackers-control-robots
  - https://www.universityofcalifornia.edu/news/misleading-text-physical-world-can-hijack-ai-enabled-robots
  - https://arxiv.org/abs/2510.00181
iocs:
  - type: ip
    value: 43.175.229.18
ioc_counts:
  ip: 1
rules:
  - title: Detect Unitree Robot Data Exfiltration
    description: Detects network connections from Unitree robots to known data exfiltration IP addresses.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
  - title: Detect Unitree Robot Command Injection via WiFi Provisioning
    description: Detects suspicious processes related to WiFi provisioning on Unitree robots that may indicate command injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Unitree Robot CloudSail Backdoor Access
    description: Detects suspicious network connections originating from CloudSail related processes, indicating potential backdoor access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Embodied AI systems, such as humanoid and quadruped robots like the Unitree Go1, Go2, B2, G1, R1, and H1 models, are increasingly integrated into various sectors, including manufacturing, logistics, and security. Research has uncovered critical vulnerabilities in these systems that allow attackers to compromise the robots remotely. These vulnerabilities include undocumented backdoors, exposed APIs, and flaws in the Bluetooth Low Energy and Wi-Fi provisioning interfaces. Successful exploitation can lead to unauthorized access, data exfiltration (including audio, video, and spatial mapping), and the potential to manipulate the robot's physical actions. The risk is heightened by the cloud-dependent architecture and centralized control mechanisms common in these platforms. These vulnerabilities enable attackers to compromise fleets of robots and create physical botnets.

## Attack Chain

1.  Attacker locates vulnerable Unitree robot via exposed API (CVE-2025-2894) due to weak or default credentials.
2.  Attacker exploits undocumented backdoor in the CloudSail service (CVE-2025-2894) to gain initial access.
3.  Attacker leverages hardcoded cryptographic keys and trivial authentication bypass in the Bluetooth Low Energy and Wi-Fi provisioning interface (UniPwn research).
4.  Attacker injects commands into the Wi-Fi setup process, achieving root-level access to the robot.
5.  Attacker uses compromised robot to wirelessly propagate the exploit to nearby Unitree robots, creating a physical botnet.
6.  Attacker exfiltrates sensitive data, including audio, video, and spatial mapping data, to an external server at IP address 43.175.229.18.
7.  Attacker bypasses normal controller and triggers physical actions, manipulating the robot's behavior.
8.  Attacker uses visual prompts injected into the robot's environment to steer autonomous driving, drone landing, and tracking tasks without compromising the underlying software.

## Impact

Compromised embodied AI systems can lead to significant data breaches, unauthorized access to sensitive environments, and potential physical harm. The Unitree G1 robot, for example, was found to continuously exfiltrate multimodal sensor data, including audio and video, every 300 seconds. A single compromised robot can enable lateral movement across nearby robots, creating a physical botnet. In a manufacturing setting, a compromised robot could disrupt production processes or cause physical damage to equipment. In security applications, a compromised robot could provide unauthorized access to facilities or be used for surveillance.

## Recommendation

*   Apply network segmentation to isolate robot networks and restrict their access to sensitive data to prevent data exfiltration as described in the overview.
*   Monitor network traffic for connections to the IP address 43.175.229.18, used for unauthorized data exfiltration by compromised Unitree G1 robots, as highlighted in the IOC section.
*   Implement strong authentication mechanisms and regularly update credentials to prevent unauthorized access through exposed APIs and backdoors, as mentioned in the attack chain description covering CVE-2025-2894.
*   Deploy the Sigma rule "Detect Unitree Robot Command Injection via WiFi Provisioning" to identify attempts to exploit the Bluetooth Low Energy and Wi-Fi provisioning interface vulnerabilities described in the attack chain.
*   Conduct regular vulnerability assessments and penetration testing of embodied AI systems to identify and remediate security weaknesses proactively.
