---
title: Potential Successful SSH Brute Force on macOS
slug: 2026-09-macos-ssh-brute-force
description: Attackers are conducting brute-force or password-spraying attacks against macOS SSH services, identified by a burst of authentication failures followed by a successful login.
date: "2026-09-15T18:58:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: A successful login immediately after repeated failures indicates that a password brute force or password spraying attack against an exposed SSH service has likely succeeded.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The threat involves attackers... using valid accounts via local account compromise.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/macos/credential_access_potential_successful_macos_ssh_bruteforce_via_security_events.toml
  - https://themittenmac.com/detecting-ssh-activity-via-process-monitoring/
rules:
  - title: Potential Successful SSH Brute Force Attack via macOS Security Events
    description: Detects a sequence of 10 or more failed SSH authentication attempts followed by a successful login within 15 seconds on a macOS host.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
      - T1110.003
    data_sources:
      - authentication
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the SSH brute force detection rule to identify active targeting.
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation on alert logic.
  hunt_leads:
    - lead: Search authentication logs for bursts of failed logins followed by success across all macOS endpoints.
      technique_id: T1110
      data_needed:
        - macOS Security Events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detection logic analysis.
  mitigation_plan:
    - priority: immediate
      action: Disable password-based SSH authentication and enforce key-based access.
      owner: IT Operations
      addresses: Credential Access / Brute Force
      evidence: Security hardening best practices.
---

This threat involves adversaries targeting macOS hosts with publicly exposed SSH services. Attackers utilize automated tools to conduct brute-force or password-spraying campaigns, attempting to gain unauthorized access by cycling through common or compromised credential pairs. The activity is characterized by a high volume of failed authentication attempts logged by the `sshd-session` process on the macOS host. Defenders can monitor this activity using macOS Security Events logs. The correlation of a rapid sequence of failure messages followed immediately by a successful `Accepted` authentication event serves as a high-fidelity indicator that an attacker has likely bypassed authentication and successfully gained access to the system. This behavior is particularly dangerous as it represents a successful breach of the perimeter, enabling subsequent malicious activity such as persistence, privilege escalation, or lateral movement.

## Attack Chain

1. Attacker performs network reconnaissance to identify internet-facing macOS hosts with TCP port 22 open.
2. Attacker initiates an automated SSH connection attempt to the target host.
3. Attacker sends authentication requests using guessed or credential-stuffed passwords.
4. macOS `sshd` logs repeated failures (e.g., "Failed password for") to the unified log.
5. Attacker eventually sends a correct credential pair that matches an existing account.
6. `sshd` records an "Accepted" authentication message indicating a successful session establishment.
7. Attacker proceeds to execute post-exploitation commands to establish persistence or exfiltrate data.

## Impact

Successful brute-force attacks on macOS hosts grant adversaries unauthorized remote access, potentially leading to full system compromise. If the targeted account has administrative privileges, the attacker may gain elevated access, facilitating malware deployment, exfiltration of sensitive files, or the use of the host as a pivot point for lateral movement within the environment.

## Recommendation

Prioritize detection and hardening to mitigate SSH-based brute-force attempts:
- Deploy the provided Sigma-compatible detection logic to SIEM platforms to monitor for failed-to-successful authentication sequences on macOS.
- Review and harden SSH configurations: disable password authentication in favor of public-key authentication, restrict SSH access using `AllowUsers` or `AllowGroups` directives, and block SSH access entirely if not required for remote management.
- Implement network-level rate limiting or geo-blocking on internet-facing SSH services.
- Reset credentials immediately for any accounts identified as targets in a successful brute-force event.
- Perform incident response procedures on compromised hosts, including searching for unauthorized SSH keys and persistence mechanisms like Launch Agents or Login Items.
