---
brief_id: brief-2026-10-lsass-access
event_id: brief-2026-10-lsass-access
revision: 1
activity_at: "2026-10-20T12:16:02Z"
title: Detection of LSASS Memory Access by Non-System Processes
slug: 2026-10-lsass-access
description: This brief provides a detection approach for identifying unauthorized access to the Local Security Authority Subsystem Service (LSASS) memory, a common technique used by attackers to harvest credentials.
date: "2026-10-20T12:16:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic based on established SIGMA community standards.
tags:
  - credential-access
  - windows
  - lsass
  - auditing
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: Detects potential mimikatz-like tools accessing LSASS from non system account
    confidence_band: high
rules:
  - title: Detect LSASS Memory Access by Non-System Process
    description: Detects potentially malicious processes attempting to access LSASS memory using handle access masks commonly associated with credential dumping tools like Mimikatz.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
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
    - action: Enable Windows Object Access Auditing for LSASS process
      owner: SOC
      due: 72h
      evidence: Required to generate Event ID 4663/4656
  hunt_leads:
    - lead: Identify processes with handles to lsass.exe that are not signed by known security vendors
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Standard credential dumping technique
---

Accessing the memory of the Local Security Authority Subsystem Service (LSASS) is a primary technique used by threat actors to perform credential dumping, allowing for the extraction of plaintext passwords, Kerberos tickets, and NTLM hashes. While legitimate security software and system services frequently interact with LSASS, malicious tools such as Mimikatz and custom credential stealers often attempt to open handles to the process with specific access masks to read its memory space. This detection focuses on Windows Security event logs (IDs 4656 and 4663) to identify when non-system, non-trusted processes request handle access to 'lsass.exe' using high-privilege access masks. Defenders should monitor for these events to differentiate between standard administrative activity or security product operations and potentially malicious credential harvesting attempts.

## Attack Chain

1. Attacker gains initial access to the Windows host through a phishing campaign or exploit.
2. Attacker executes an unauthorized process or script under a non-system user context.
3. Attacker identifies the process ID (PID) of 'lsass.exe' via system enumeration.
4. Attacker attempts to open a handle to 'lsass.exe' using Windows APIs (e.g., OpenProcess).
5. The attacker requests specific access masks (e.g., 0x1f0fff) intended for memory reading.
6. The Windows Security subsystem generates Event ID 4656 or 4663 due to Object Access Auditing policies.
7. If successful, the attacker dumps LSASS process memory to disk or extracts credentials into the tool's buffer.
8. Attacker exfiltrates the harvested credentials for lateral movement or domain privilege escalation.

## Impact

Successful exploitation of LSASS memory access enables an attacker to obtain cleartext credentials or cryptographic material. This typically results in full domain compromise, as the attacker can impersonate highly privileged users, move laterally through the network, and maintain persistence. This behavior is commonly observed in the post-exploitation phases of ransomware attacks, APT-led espionage, and targeted data breaches.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for unauthorized access attempts to LSASS.
* Ensure "Audit Object Access" and "Audit Handle Manipulation" are enabled via Group Policy to generate Event IDs 4656 and 4663.
* Use the filter list in the Sigma rule to baseline and exclude known-good security products and system processes operating in your specific environment.
* Investigate any triggered events involving processes not located in protected paths (e.g., 'C:\Program Files\').
