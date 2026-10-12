---
title: Detection of Rundll32 Inline HTA Execution
slug: 2026-10-rundll32-inline-hta
description: Adversaries leverage rundll32.exe with inline protocol handlers like VBScript or JavaScript to execute fileless payloads and bypass security controls.
date: "2026-10-12T17:41:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This technique is often associated with fileless malware or application whitelisting bypass techniques.
    confidence_band: high
rules:
  - title: Detect Rundll32 Inline HTA Execution
    description: Detects the execution of rundll32.exe with inline protocol handlers like JavaScript or VBScript, often used for fileless execution or bypasses.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
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
    - action: Deploy Sigma detection rule to SIEM and tune for environment-specific legitimate usage.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for rundll32 inline execution.
  hunt_leads:
    - lead: Search for rundll32 processes with script-related protocol strings in the command line.
      technique_id: T1218.005
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used for LotL attacks.
---

Attackers frequently utilize the legitimate Windows binary 'rundll32.exe' to execute malicious code via inline protocol handlers, specifically leveraging VBScript, JavaScript, or the 'About' protocol. This technique facilitates fileless malware execution and effectively bypasses application whitelisting and traditional signature-based security controls. By embedding scripts directly into the command line, actors can maintain persistence and execute arbitrary payloads without dropping traditional executable files to the disk. This activity is a known component of various campaigns, including those attributed to NOBELIUM, APT37, and broader 'Living Off The Land' (LotL) tactics. Security teams must monitor command-line arguments of rundll32.exe to detect instances where it is invoked with script-based protocols instead of its intended function of executing DLL exports.

## Attack Chain

1. Initial access is established, often via a spearphishing email with a malicious document or a drive-by download.
2. The attacker triggers a secondary stage, such as a script embedded in a document or a malicious link.
3. The attacker invokes 'rundll32.exe' from the command line or via a script launcher.
4. The command line includes an inline handler such as 'vbscript:' or 'javascript:' to point to the malicious payload.
5. Rundll32.exe processes the inline script, bypassing standard file integrity checks.
6. Malicious code executes in memory, providing a foothold for C2 communication or credential theft.
7. The attacker ensures persistence through scheduled tasks or registry modifications.

## Impact

Successful execution of this technique allows for stealthy code execution, potential credential harvesting, and long-term persistence within the target environment. Because the primary process is a legitimate system binary, it is often overlooked by legacy security monitoring, increasing the dwell time for adversaries. This technique has been documented in operations targeting diverse sectors by advanced persistent threat groups.

## Recommendation

Prioritize the deployment of the provided Sigma rule to monitor for suspicious rundll32.exe command-line arguments. Enable Sysmon or Windows Security event logs to capture command-line telemetry across all endpoints. Conduct periodic threat hunting for rundll32.exe processes exhibiting unexpected parent-child relationships or anomalous command-line usage. Ensure EDR tools are tuned to alert on instances of script handlers used as parameters for system binaries.
