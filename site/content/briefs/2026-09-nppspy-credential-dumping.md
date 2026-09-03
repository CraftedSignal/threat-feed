---
title: Credential Dumping via Malicious Network Provider Registration
slug: 2026-09-nppspy-credential-dumping
description: Adversaries can exploit the Windows Network Provider architecture by registering malicious DLLs to intercept and dump cleartext credentials during user authentication events.
date: "2026-09-03T12:42:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/network-provider-settings-removed-in-place-upgrade
  - https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy
rules:
  - title: Detect Potential Credential Dumping via New NetworkProvider Registration
    description: Detects the creation or modification of a network provider registry path via command line, a technique used by NPPSpy to capture cleartext credentials.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy registry monitoring for HKLM\System\CurrentControlSet\Services\*\NetworkProvider
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical basis for registration-based persistence
  hunt_leads:
    - lead: Search for existing registry keys under System\CurrentControlSet\Services\ that are not in the standard allowlist
      technique_id: T1003
      data_needed:
        - Endpoint registry snapshots
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker registry modification requirement
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrator rights to prevent registry modifications
      owner: IT Operations
      addresses: Persistence and credential dumping
      evidence: Attacker requires elevated privileges
---

Adversaries may attempt to gain persistent access to cleartext credentials by manipulating the Windows Network Provider (NP) subsystem. By adding a malicious entry to the registry under the NetworkProvider key, an attacker can force Windows to load a rogue DLL whenever a user logs in or authenticates. This technique, notably implemented by the NPPSpy tool, allows the malicious library to act as a man-in-the-middle, capturing credentials as they pass through the provider interface. Because the Network Provider is a core system component, this method facilitates both credential theft and stealthy persistence, as the malicious library is loaded into the context of legitimate system processes like winlogon.exe.

## Attack Chain

1. Attacker gains elevated (Administrator or SYSTEM) privileges on the target Windows host.
2. Attacker prepares a malicious DLL designed to implement the Network Provider interface.
3. Attacker drops the malicious DLL to a filesystem location (e.g., C:\Windows\System32\).
4. Attacker modifies the registry key HKLM\System\CurrentControlSet\Services\ to create a new subkey for the provider.
5. Attacker adds a NetworkProvider subkey with a 'ProviderOrder' or similar registration.
6. Attacker points the 'Path' or 'DLLName' value within the registry to the malicious library.
7. Upon the next user login or network authentication event, the Windows service controller loads the malicious DLL.
8. The malicious code hooks the authentication function, captures the cleartext credentials, and exfiltrates them.

## Impact

Successful exploitation leads to the compromise of cleartext user credentials, potentially allowing for lateral movement, privilege escalation, and domain-wide compromise within an enterprise network.

## Recommendation

* Deploy the Sigma rule below to monitor for registry-based registration of unauthorized network providers using the command line.
* Audit existing keys under HKLM\System\CurrentControlSet\Services\ for unexpected NetworkProvider configurations.
* Establish a baseline of authorized network providers in the environment and alert on any additions.
