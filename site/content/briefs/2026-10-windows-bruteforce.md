---
title: Windows Brute Force and Password Spraying Detection
slug: 2026-10-windows-bruteforce
description: Adversaries are leveraging high-volume network logon failures against Windows systems to brute force or spray credentials, often targeting multiple accounts from a single source IP.
date: "2026-10-06T17:59:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - brute-force
  - windows
  - threat-detection
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Adversaries will often brute force login attempts across multiple users with a common or known password.
    confidence_band: high
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1110/003/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy ES|QL rule for high-frequency failed logon detection.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides query to detect multiple logon failures from same IP.
  hunt_leads:
    - lead: Identify source IPs with > 100 failed logins in 60s windows.
      technique_id: T1110
      data_needed:
        - Windows Security Event Logs (Event ID 4625)
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Rule logic requires aggregating 60-second windows of failed logins.
---

Adversaries with no prior knowledge of legitimate system credentials frequently attempt to gain unauthorized access to Windows accounts through systematic password guessing. This activity, categorized as brute force or password spraying (T1110.001/T1110.003), involves repetitive authentication requests against target systems. Defenders observe this behavior as a rapid spike in Windows Security Event ID 4625 (Logon Failure) entries originating from a singular source IP address. 

When this activity manifests, it often targets multiple distinct usernames within a very short timeframe. This threat is particularly significant for internet-facing assets or systems with exposed management interfaces such as RDP. If left undetected, successful authentication grants the adversary an initial foothold, allowing for further internal reconnaissance, privilege escalation, and exfiltration. This detection-focused brief addresses the need to monitor for high-frequency failed logon patterns while filtering out common configuration-related noise such as expired service account credentials or synchronization errors between domain controllers.

## Attack Chain

1. Attacker performs reconnaissance to identify network-accessible Windows hosts via scanning tools (e.g., Nmap or custom scanners).
2. Attacker establishes a connection to the target Windows system using network-based protocols like RDP or SMB.
3. Attacker initiates an automated script to submit consecutive authentication attempts (Logon Type 3: Network) using a wordlist of common passwords.
4. Target Windows host logs these unsuccessful attempts under Security Event ID 4625, documenting the source IP, target username, and failure status code.
5. Attacker iterates through multiple user accounts (Password Spraying) to maximize the probability of success while attempting to bypass account lockout thresholds.
6. If a correct credential pair is guessed, the target host generates a successful logon event (Event ID 4624).
7. Attacker proceeds to establish persistence, move laterally, or deploy additional malware once inside the environment.

## Impact

Successful brute force or password spraying attacks lead to unauthorized account compromise, potentially providing adversaries with administrative access to the domain. This can result in large-scale data exfiltration, ransomware deployment, and lateral movement. Organizations are at risk of complete account takeover if multi-factor authentication is not strictly enforced on network-facing services.

## Recommendation

1. Enable Windows Audit Logon policies to capture Event ID 4625 across all endpoints.
2. Deploy the provided ES|QL rule to the Elastic Stack to aggregate logon failures over 60-second windows and flag source IPs exceeding 100 failures targeting two or more accounts.
3. Investigate source IPs flagged by the detection to determine if they originate from internal automation or malicious external actors.
4. If the source is confirmed as malicious, isolate the affected host and implement firewall blocks for the offending IP address.
5. Enforce strong authentication mechanisms and ensure all internet-exposed remote services are protected by MFA.
