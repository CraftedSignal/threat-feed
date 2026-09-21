---
title: Detection of Malicious Kernel-Mode Driver Installation
slug: 2026-09-windows-vulnerable-driver-loading
description: Adversaries install and load known vulnerable Windows kernel-mode drivers to achieve privilege escalation or kernel-level persistence.
date: "2026-09-21T19:12:56Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries often exploit vulnerable drivers to gain elevated privileges or maintain persistence on a system.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: The following analytic detects the loading of known vulnerable Windows drivers, which may indicate potential persistence or privilege escalation attempts.
    confidence_band: high
references:
  - https://loldrivers.io/
  - https://github.com/SpikySabra/Kernel-Cactus
  - https://github.com/wavestone-cdt/EDRSandblast
  - https://research.splunk.com/endpoint/a2b1f1ef-221f-4187-b2a4-d4b08ec745f4/
rules:
  - title: Detect Installation of Known Vulnerable Windows Drivers
    description: Detects the installation of a kernel-mode driver service (Event ID 7045) that matches a known vulnerable driver path.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule to monitor System Event 7045 for suspicious ImagePath strings.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for Event 7045 monitoring.
  hunt_leads:
    - lead: Search for kernel-mode driver installations outside of standard System32 paths.
      technique_id: T1543.003
      data_needed:
        - Event ID 7045 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known vulnerable drivers are often dropped in non-standard user-accessible paths.
---

Adversaries frequently employ the installation of known vulnerable Windows drivers as a mechanism to facilitate privilege escalation and persistence. By loading a driver with documented security vulnerabilities into the kernel, an attacker can bypass security controls, disable EDR protections, or execute arbitrary code with SYSTEM-level privileges. This technique relies on the abuse of legitimate, signed drivers that contain exploitable flaws, often documented within open-source projects such as loldrivers.io. Defenders must monitor for the installation of kernel-mode services, specifically Event ID 7045, and perform lookups against databases of known malicious or vulnerable binary paths to differentiate legitimate system drivers from those introduced for adversarial purposes. This activity is a critical indicator of post-exploitation phases aimed at gaining total system control.

## Attack Chain

1. Attacker gains administrative access to the target endpoint.
2. Attacker stages a vulnerable, legitimate, but exploitable driver binary on the local disk.
3. Attacker uses legitimate Windows service management tools (e.g., sc.exe) to install the driver as a system service.
4. The operating system generates a System Event ID 7045 entry indicating a new kernel-mode driver service has been registered.
5. The driver is loaded into the kernel memory space by the Service Control Manager.
6. Attacker interacts with the vulnerable driver (often via IOCTL codes) to trigger an exploitation primitive.
7. The vulnerability is exploited to achieve arbitrary kernel-mode code execution.
8. Attacker disables security software or modifies system structures to maintain persistent, elevated control.

## Impact

Successful exploitation of vulnerable kernel-mode drivers allows attackers to bypass kernel-mode code signing requirements, disable endpoint security agents, and operate with the highest possible privileges on the host. This facilitates long-term persistence, data exfiltration, and full control over the compromised asset.

## Recommendation

1. Enable Windows System Event Logging, specifically for Event ID 7045.
2. Implement a lookup table containing the file paths or hash signatures of known vulnerable drivers as identified in the loldrivers project.
3. Deploy the provided Sigma rule to alert on the registration of kernel-mode drivers that match the defined vulnerable criteria.
4. Perform periodic threat hunting for unsigned or suspicious drivers installed in temporary directories or non-standard paths.
