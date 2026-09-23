---
title: Detection of LSASS Process Handle Access via Windows API
slug: 2026-09-lsass-api-access
description: This brief describes the detection of unauthorized access to the LSASS process handle via OpenProcess, OpenThread, and ReadProcessMemory API calls, a technique used by adversaries to facilitate credential dumping.
date: "2026-09-23T01:17:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - endpoint
  - detection
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Adversaries may attempt to access the LSASS handle to dump credentials from its memory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
    evidence: This rule identifies attempts to access LSASS by monitoring for specific API calls (OpenProcess, OpenThread) targeting the lsass.exe process.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_lsass_openprocess_api.toml
  - https://attack.mitre.org/techniques/T1003/001/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy ES|QL rule provided in source to identify unauthorized API calls to LSASS.
      owner: Detection Engineering
      due: 48h
      evidence: Source rule requirement for endpoint activity monitoring.
  hunt_leads:
    - lead: Search for rare processes accessing LSASS via API calls.
      technique_id: T1003.001
      data_needed:
        - Endpoint API monitoring telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source detection rule logic.
  mitigation_plan:
    - priority: short_term
      action: Restrict process handle access via EDR and host-based security policies.
      owner: IT Operations
      addresses: Credential dumping via LSASS memory access.
      evidence: General security hardening for identity protection.
---

The Local Security Authority Subsystem Service (LSASS) is a critical Windows component responsible for managing user authentication and security policies. Adversaries often target the LSASS process handle to extract authentication material (such as NTLM hashes or Kerberos tickets) from memory. This process, known as credential dumping, is a foundational step for lateral movement and privilege escalation.

The detection logic focuses on monitoring sensitive Windows API calls - specifically OpenProcess, OpenThread, and ReadProcessMemory - when they target 'lsass.exe'. This approach is highly effective at identifying unauthorized access attempts originating from non-standard or suspicious processes. To ensure signal quality, the detection logic includes filtering for legitimate software paths and common Windows updates, while focusing on rare, low-frequency access events that are statistically likely to be unauthorized. Defenders should investigate the process lineage, digital signatures, and access rights requested by the calling process to distinguish legitimate administrative activity from malicious credential access.

## Attack Chain

1. An adversary gains initial code execution on a Windows host via an exploited service or malicious file.
2. The adversary attempts to interact with protected system processes to gain higher-level privileges.
3. The adversary process calls the 'OpenProcess' API with high-level access masks targeting 'lsass.exe'.
4. The adversary process calls 'ReadProcessMemory' to copy the memory contents of 'lsass.exe' into the malicious process's address space.
5. The malicious process may utilize a tool (e.g., Mimikatz, procdump) to parse the dumped memory for credentials.
6. Credentials (passwords, hashes, or tickets) are exfiltrated or used immediately for lateral movement.
7. The adversary maintains persistence while using the stolen credentials to move laterally within the domain.

## Impact

Successful exploitation of LSASS memory allows adversaries to capture plaintext credentials, NTLM hashes, and Kerberos tickets. This facilitates lateral movement, privilege escalation, and domain-wide compromise. Unauthorized memory access poses a critical risk to identity security, enabling attackers to impersonate privileged users and maintain long-term access within the environment.

## Recommendation

- Deploy the detection logic within an Elastic SIEM environment configured for ES|QL to identify rare API calls targeting LSASS.
- Investigate the process lineage of any process triggering an alert; prioritize unsigned executables or those located in non-standard directories.
- Utilize Osquery to audit current system services for unsigned executables or suspicious user accounts as identified in the investigation guide.
- Enforce strict monitoring of 'ReadProcessMemory' and 'OpenProcess' events targeting 'lsass.exe' across all high-value Windows endpoints.
- Validate that identified processes have a legitimate business purpose; block and isolate hosts if malicious intent (such as credential dumping) is confirmed through subsequent forensic triage.
