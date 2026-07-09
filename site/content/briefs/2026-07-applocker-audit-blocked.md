---
title: AppLocker Audit Events Indicate Potential Policy Violations
slug: 2026-07-applocker-audit-blocked
description: This brief describes the detection of Windows AppLocker audit events (Event IDs 8003, 8006, 8021, 8024) that indicate applications, DLLs, scripts, MSIs, or packaged apps would have been blocked by an active AppLocker policy, providing insight into unauthorized software execution attempts or policy violations in audit mode.
date: "2026-07-09T14:04:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - applocker
  - audit
  - windows-security
  - application-control
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: AppLocker audit event (EventID 8003, 8006, 8021, 8024) indicates execution of an application, DLL, MSI, or packaged app would have been blocked.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: AppLocker audit event (EventID 8006) indicates execution of a script, potentially a PowerShell script, would have been blocked.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: AppLocker audit event (EventID 8006) indicates execution of a script, potentially via the Windows Command Shell, would have been blocked.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: AppLocker audit event (EventID 8006) indicates execution of a script, potentially a Visual Basic script, would have been blocked.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: AppLocker audit event (EventID 8006) indicates execution of a script, potentially a Python script, would have been blocked.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: AppLocker audit event (EventID 8006) indicates execution of a script, potentially a JavaScript/JScript, would have been blocked.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/what-is-applocker
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/using-event-viewer-with-applocker
  - https://www.splunk.com/en_us/blog/security/deploy-test-monitor-mastering-microsoft-applocker-part-2.html
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ee844150(v=ws.11)
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml
rules:
  - title: AppLocker Application Would Have Been Blocked
    description: Detects when AppLocker audit mode reports that an application, DLL, script, MSI, or packaged app would have been blocked by an active AppLocker policy.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1059.005
      - T1059.006
      - T1059.007
      - T1204.002
    data_sources:
      - event_logging
      - windows
      - applocker
rules_count: 1
---

This brief focuses on the detection of Windows AppLocker audit events (Event IDs 8003, 8006, 8021, 8024), which signify that applications, DLLs, scripts, MSIs, or packaged applications would have been blocked if AppLocker policies were in 'Enforce rules' mode. These events, generated while AppLocker operates in 'Audit only' mode, provide critical intelligence to security operations centers (SOCs) and detection engineers. By monitoring these specific event IDs, organizations can proactively identify potential policy violations, unauthorized software execution attempts, or even malware activity without disrupting legitimate business processes. This allows for thorough testing and refinement of AppLocker policies before full enforcement, ensuring that only intended applications are permitted while malicious or unapproved software is flagged.

## Impact

When AppLocker is configured in 'Audit only' mode, no applications are actively blocked. However, the generation of these audit events (8003, 8006, 8021, 8024) provides invaluable insight into what *would* have been blocked under an enforced policy. The primary impact is the ability to thoroughly test and refine AppLocker policies without user disruption, which can reveal widespread usage of unsanctioned applications or previously undetected malware. Failure to monitor these audit events means losing a crucial opportunity to identify potential attack vectors, unauthorized software installations, or attempts by adversaries to execute malicious code, all of which would lead to successful execution if the policies were later enforced without prior tuning. This capability allows security teams to proactively strengthen their application control posture and prevent future breaches.

## Recommendation

* Deploy the Sigma rule "AppLocker Application Would Have Been Blocked" to your SIEM solution to identify potential policy violations in AppLocker audit mode.
* Ensure that Windows AppLocker event logging for `Microsoft-Windows-AppLocker/EXE and DLL` and `Microsoft-Windows-AppLocker/MSI and Script` is enabled and forwarded to your central logging system.
* Tune the deployed Sigma rule for the specific `logsource` and expected false positives within your environment, especially during AppLocker policy testing phases.
