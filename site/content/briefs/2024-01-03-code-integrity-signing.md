---
title: Code Integrity - Unmet Signing Level Requirements
slug: 2024-01-03-code-integrity-signing
description: Windows Code Integrity events 3033 and 3034 indicate an attempted file load that failed to meet the configured signing level requirements, potentially due to revoked signatures or expired certificates, signaling a possible attempt to load unsigned or untrusted code.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - codeintegrity
  - windows
  - execution
vendors:
  - Microsoft
products:
  - Windows
  - Windows Defender Application Control
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://twitter.com/SBousseaden/status/1483810148602814466
  - https://github.com/MicrosoftDocs/windows-itpro-docs/blob/40fe118976734578f83e5e839b9c63ae7a4af82d/windows/security/threat-protection/windows-defender-application-control/event-id-explanations.md#windows-codeintegrity-operational-log
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
rules:
  - title: CodeIntegrity - Unmet Signing Level Requirements - Generic
    description: Detects attempted file load events that did not meet the signing level requirements. It often means the file's signature is revoked or a signature with the Lifetime Signing EKU has expired.
    platform: sigma
    severity: low
    tactics:
      - execution
    data_sources:
      - process_creation
      - windows
  - title: CodeIntegrity - Unmet Signing Level Requirements - Specific DLL
    description: Detects attempts to load a specific DLL that does not meet signing level requirements. Useful for identifying potential malicious DLL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Windows Code Integrity (CI) is a security feature that validates the integrity of code before it is allowed to execute. Events 3033 and 3034 within the Code Integrity operational log signal situations where a process attempted to load a file that did not meet the configured signing level requirements. This can occur if the file's signature is invalid, revoked, or if a time-stamping signature has expired. This is often observed with legitimate software, but can also indicate attempts to load unsigned or improperly signed malicious code, potentially bypassing security controls. These events should be correlated with Event ID 3089 to determine the error of the validation. Due to the high number of false positives, careful filtering and tuning is required.

## Attack Chain

1.  An attacker attempts to execute a payload, often a DLL or other executable file, that is either unsigned, has a revoked signature, or whose signature has expired.
2.  The operating system's code integrity subsystem intercepts the file load operation.
3.  Code Integrity validates the signing level of the file against the configured policy.
4.  If the signing level requirements are not met (e.g., invalid signature, expired certificate), Code Integrity logs Event ID 3033 (if blocking) or 3034 (if auditing).
5.  If blocking, the file load operation is prevented, hindering the execution of the malicious code. If auditing, the file load is allowed but logged.
6.  The attacker's attempt to execute the malicious payload is either blocked or allowed based on the Code Integrity policy.
7.  If allowed (Event ID 3034), the malicious code may execute, potentially leading to arbitrary code execution, privilege escalation, or other malicious activities.

## Impact

While the events themselves do not directly cause harm, they indicate potential attempts to bypass code integrity controls. Success in loading unsigned or improperly signed code can lead to arbitrary code execution, potentially enabling attackers to escalate privileges, deploy malware, or compromise system integrity. These events are noisy, and commonly triggered by legitimate software with expired or invalid signatures. The actual impact depends on whether the file load was blocked (Event ID 3033) or allowed (Event ID 3034).

## Recommendation

*   Enable the Code Integrity operational log in Windows to collect Event IDs 3033 and 3034.
*   Deploy the provided Sigma rule to detect instances of unmet signing level requirements and tune the filters to reduce false positives related to specific software in the environment.
*   Investigate instances where Event ID 3034 is logged, as this indicates that unsigned or improperly signed code was allowed to load.
*   Correlate Event IDs 3033 and 3034 with Event ID 3089, as recommended in the overview, to determine the underlying reason for the signing level failure and accurately differentiate malicious and benign activity.
*   Prioritize investigation of events where the `FileNameBuffer` does not match known good paths for third-party software to reduce false positives mentioned in the Sigma rule's `falsepositives` section.
