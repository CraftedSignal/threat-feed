---
title: COM Hijacking via TreatAs Registry Modification
slug: 2026-09-com-hijacking-treatas
description: Adversaries leverage the COM TreatAs registry key to achieve persistence or privilege escalation by redirecting CLSID lookups to malicious COM objects.
date: "2026-09-01T12:14:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - registry-tampering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.015
    technique_name: Component Object Model Hijacking
    evidence: Attacker modifies the TreatAs key to enable rundll32.exe execution.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md
  - https://www.youtube.com/watch?v=3gz1QmiMhss&t=1251s
rules:
  - title: Detect COM Hijacking via TreatAs
    description: Detects modification of the TreatAs registry key which is used to redirect COM object instantiation for persistence or execution
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.015
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect registry changes
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify all processes modifying CLSID registry keys
      technique_id: T1546.015
      data_needed:
        - registry_set logs
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: medium
      action: Enable strict monitoring on HKLM\Software\Classes\CLSID keys
      owner: IT Operations
---

COM Hijacking via the TreatAs registry key is a persistence and privilege escalation technique that exploits the Component Object Model (COM) in Windows. The TreatAs key allows a specific Class Identifier (CLSID) to be treated as another CLSID, effectively redirecting calls meant for a legitimate object to a different, attacker-controlled object. By modifying these registry entries, an attacker can ensure their malicious code is executed whenever a legitimate application attempts to instantiate the hijacked COM object. This technique is often used to execute payloads via rundll32.exe. Defenders should monitor registry modifications to CLSID keys, specifically focusing on the TreatAs subkey, while accounting for legitimate system updates or software installations that might produce similar registry changes.

## Attack Chain

1. Attacker identifies a target CLSID that is frequently invoked by system processes or administrative applications.
2. Attacker creates a new, malicious COM object with a unique CLSID or repurposes an existing one.
3. Attacker modifies the registry key for the target CLSID by adding or updating the TreatAs subkey.
4. The registry value is set to the CLSID of the malicious COM object.
5. A legitimate application invokes the original COM object using its standard CLSID.
6. The COM subsystem resolves the request using the hijacked TreatAs mapping.
7. The system instantiates the malicious COM object instead of the intended one.
8. The malicious code executes, resulting in persistence or elevated execution context.

## Impact

Successful exploitation allows attackers to maintain persistent access to a compromised system or execute code with the privileges of the application invoking the COM object. This technique can lead to stealthy code execution that bypasses standard startup folder or Run key monitoring.

## Recommendation

Deploy detection rules to monitor registry modification events targeting the TreatAs subkey. Establish baselines for known-good installers (like msiexec.exe and Office Click-to-Run) to reduce noise. Investigate any unexpected processes modifying these keys.

* Deploy the Sigma rule provided in this brief to your SIEM.
* Enable Windows registry auditing (SACL) for key creation and value modifications on HKLM and HKU classes hives.
* Use the Atomic Red Team test (T1546.015) in your lab to validate detection coverage.
