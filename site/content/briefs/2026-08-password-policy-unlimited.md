---
title: Windows Password Policy Modification to Unlimited via Net.exe
slug: 2026-08-password-policy-unlimited
description: Adversaries use 'net accounts /maxpwage:unlimited' to disable password expiration policies on Windows hosts, effectively ensuring compromised credentials remain valid for long-term persistence.
date: "2026-08-24T15:46:45Z"
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
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1489
    technique_name: Service Stop
    evidence: The analytic detects the use of net.exe or net1.exe to configure the Windows maximum password age policy as unlimited, which may indicate an attempt to establish or maintain persistence.
    confidence_band: high
references:
  - https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
  - https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems
rules:
  - title: Detect Windows Password Policy Modification via Net.exe
    description: Detects the use of net.exe or net1.exe to set the maximum password age policy to unlimited.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1489
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
    - action: Deploy the Sigma rule to monitor for password policy changes.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection documentation
  hunt_leads:
    - lead: Search for historical process creation events involving 'net accounts' and 'unlimited'.
      technique_id: T1489
      data_needed:
        - Endpoint process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Analytic describes this as high-fidelity.
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative rights to the 'net' utility to authorized personnel.
      owner: IT Operations
      addresses: T1489
      evidence: Technique relies on account privileges
---

Adversaries and commodity malware frequently leverage the built-in Windows `net.exe` or `net1.exe` utilities to weaken security posture during post-exploitation activities. By executing the command `net accounts /maxpwage:unlimited`, an attacker forces the local or domain password policy to stop enforcing expiration requirements. This prevents security controls like forced password rotations from invalidating credentials that the attacker has compromised. This technique is often observed as part of a persistence mechanism, allowing the actor to maintain stable access to a victim's account for extended periods without needing to re-authenticate or re-compromise the user. Defenders should treat this command as a high-fidelity indicator of credential maintenance activity rather than routine administrative work, as such policy modifications are rarely performed in production environments.

## Attack Chain

1. Initial compromise of a host, often through credential dumping or malicious payload execution.
2. Execution of a shell or command-line interface (e.g., cmd.exe, powershell.exe) by the malicious process.
3. The malicious process invokes `net.exe` or `net1.exe` using a child process creation event.
4. The attacker passes the arguments `accounts` followed by `/maxpwage:unlimited` to the utility.
5. The Windows Service Control Manager or Netlogon service processes the request to update the SAM or Active Directory object policy.
6. The system configuration is updated to ignore expiration intervals for user accounts.
7. The attacker maintains long-term, uninterrupted access to the account, bypassing organizational password rotation requirements.

## Impact

Successful execution of this command results in a weakened security posture by disabling mandatory password rotation. This allows attackers to maintain persistence on compromised accounts for an indefinite period, increasing the risk of data exfiltration and further lateral movement. This activity is frequently associated with ransomware operators and crypto-stealing malware attempting to lock in access to infected environments.

## Recommendation

1. Deploy the provided Sigma rule to detect the execution of `net accounts` with the `maxpwage` parameter.
2. Implement auditing for process creation events (Event ID 4688 or Sysmon Event ID 1) that include command-line arguments to ensure visibility into the full utility path and parameters.
3. Investigate any instances of `net.exe` spawning from non-administrative processes or unexpected parent binaries (e.g., malware droppers).
4. Use the `drilldown_searches` provided in security monitoring platforms to review the history of affected endpoints and identify related malicious activity, such as risk events from the preceding 7 days.
