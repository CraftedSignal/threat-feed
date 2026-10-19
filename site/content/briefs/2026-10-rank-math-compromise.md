---
title: Supply Chain Compromise of Rank Math PRO WordPress Plugin
slug: 2026-10-rank-math-compromise
description: Attackers compromised Rank Math PRO version 3.0.123 between October 15 and October 16, 2026, injecting malware that provides persistent administrative access, credential theft, and server-side backdoor capabilities.
date: "2026-10-19T16:19:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - wordpress
  - plugin-compromise
vendors:
  - Rank Math
products:
  - Rank Math PRO (3.0.123)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Users downloaded malicious versions of Rank Math PRO last week, after the WordPress SEO plugin was compromised in a supply chain attack.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: its persistence mechanism could make manual cleanup a difficult task.
    confidence_band: high
iocs:
  - type: domain
    value: rank1cdn.com
ioc_counts:
  domain: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Check all WordPress instances for Rank Math PRO v3.0.123 and update to v3.0.124 or later.
      owner: IT Operations
      due: 24h
      evidence: We immediately removed the affected files and released a clean version, Rank Math PRO v3.0.124
    - action: Block rank1cdn.com at the DNS level.
      owner: SOC
      due: 24h
      evidence: block the attacker’s domain rank1cdn[.]com
  hunt_leads:
    - lead: Identify unauthorized admin accounts created since October 15, 2026.
      technique_id: T1136.002
      data_needed:
        - WordPress database users table
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: find and remove ... unknown administrator accounts.
  mitigation_plan:
    - priority: immediate
      action: Restore site from clean backup created prior to October 15.
      owner: IT Operations
      addresses: Entire WordPress compromise
      evidence: restore them from a clean backup created before the incident.
---

Between October 15 and October 16, 2026, attackers successfully compromised the supply chain for the Rank Math PRO WordPress plugin, specifically version 3.0.123. Users who downloaded or updated to this version during the window (20:02 UTC on October 15 to 07:12 UTC on October 16) received packages containing malicious code. Once activated, the malware grants attackers persistent administrative access, the ability to exfiltrate credentials and API keys, and creates backdoors within the compromised WordPress environment. The persistence mechanisms are multifaceted, including database modifications, fake core files, and .htaccess manipulations, making manual remediation complex. This incident underscores the risks inherent in third-party plugin updates and the potential for broad, automated compromise via supply chain vectors.

## Attack Chain

1. Attacker compromises the build or distribution channel of Rank Math PRO version 3.0.123.
2. Victim administrator downloads or updates the plugin during the period of compromise.
3. Activation of the malicious plugin allows for initial execution of embedded PHP scripts.
4. Malware drops malicious .cache files containing PHP payloads and injects fake WordPress core files.
5. The attacker modifies .htaccess files to ensure .cache files are executed as PHP code upon page visits.
6. Malware creates a hidden backdoor, registers persistent tasks or cron jobs, and creates unauthorized administrator accounts.
7. Attacker exfiltrates sensitive data including API keys, database credentials, and site secrets.
8. Persistent access is maintained across page loads and potential site updates via the deployed backdoors.

## Impact

Victims of this compromise face a total takeover of their WordPress websites. The malware enables the exfiltration of sensitive site data, including credentials and API keys, and establishes deep persistence that survives typical plugin removal. Impacted users must perform a full site restoration from a clean backup to ensure the removal of attacker-controlled backdoors, cron jobs, and unauthorized administrative users.

## Recommendation

1. Immediately verify the version of the Rank Math PRO plugin and update to version 3.0.124 or later if running 3.0.123.
2. Block outbound traffic to the known attacker domain 'rank1cdn.com' at the network perimeter.
3. Conduct a forensic review of the web server for unauthorized PHP files, modifications to .htaccess files, and unrecognized scheduled cron jobs.
4. Audit the WordPress administrative user list for unauthorized accounts created during or after the compromise window.
5. Force a password reset for all administrative users and rotate all API keys and secrets stored within the WordPress environment.
6. Restore the entire website from a known-clean backup created prior to October 15, 2026, as manual cleanup may be incomplete.
