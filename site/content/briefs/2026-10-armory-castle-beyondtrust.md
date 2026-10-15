---
title: ARMORY CASTLE Exploitation of BeyondTrust Remote Support
slug: 2026-10-armory-castle-beyondtrust
description: The PRC-nexus actor ARMORY CASTLE is exploiting the arbitrary file upload vulnerability CVE-2026-102764 in BeyondTrust Remote Support appliances to deploy web shells, escalate privileges, and harvest credentials.
date: "2026-10-15T22:20:03Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - ARMORY CASTLE
exploited: true
cpes:
  - cpe:2.3:a:beyondtrust:remote_support:*:*:*:*:*:*:*:*
tags:
  - espionage
  - webshell
  - cve-2026-102764
  - beyondtrust
vendors:
  - BeyondTrust
products:
  - Remote Support
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The successful exploitation of this vulnerability results in the arbitrary upload of files.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Setuid and Setgid
    evidence: The threat actor then modified the file's ownership to root and enabled Set User ID (SUID) permissions.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Systemd Service
    evidence: For long-term persistent access, Mandiant observed the threat actor target the BeyondTrust configuration templates to grant passwordless root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-102764
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust/
  - https://www.beyondtrust.com/trust-center/security-advisories/bt26-05
rules:
  - title: Detect SAWFLY Webshell Execution
    description: Detects potential SAWFLY webshell activity by identifying the specific parameter _c94mfe in incoming HTTP requests
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
  - title: Detect SUID File Manipulation
    description: Detects the creation or modification of SUID files, a technique used by ARMORY CASTLE for privilege escalation
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch BeyondTrust Remote Support appliances to the version specified in BT26-05
      owner: IT Operations
      due: 24h
      evidence: Mandiant strongly recommends that affected organizations immediately apply the security patches
  mitigation_plan:
    - priority: immediate
      action: Upgrade BeyondTrust Remote Support appliance firmware
      owner: IT Operations
      addresses: CVE-2026-102764
      evidence: BeyondTrust security advisory BT26-05
---

In late August 2026, the threat actor ARMORY CASTLE (formerly tracked as UNC5221) began exploiting a zero-day vulnerability, CVE-2026-102764, in BeyondTrust Remote Support appliances. This vulnerability allows for arbitrary file uploads, enabling the actor to achieve remote code execution. Upon gaining an initial foothold, the actor deployed the custom SAWFLY PHP webshell to interact with the device. ARMORY CASTLE demonstrated extensive knowledge of the appliance's internals, utilizing proprietary binaries such as 'bt-secrets' to extract sensitive credentials from the native vault. The actor maintains persistence and ensures root-level control by manipulating SUID permissions and modifying startup configuration templates. These intrusions represent a sophisticated effort to gain persistent access to enterprise remote support infrastructure, facilitating potential lateral movement and long-term espionage within target organizations.

## Attack Chain

1. Attacker exploits the arbitrary file upload vulnerability CVE-2026-102764 by initiating POST requests to the endpoint '/app_84304470.php'.
2. The SAWFLY webshell ('mangoapi.php') is written to the web root path '/%SITE_SERVICE_ACCOUNT%/ingredi/app/laravel/public/'.
3. The actor executes commands via the webshell under the unprivileged site service account.
4. Privilege escalation is achieved by copying '/bin/sh' to '/usr/bin/dbus-authd' and setting the SUID bit on the file.
5. The actor leverages the administrative CLI utility '/ns/sbin/bt-secrets' to dump administrative passwords and API keys from the appliance vault.
6. Persistence is established by creating a startup script 'zz-root-persist' in the '/home/bomgar/sbin/post_boot.d' directory.
7. Artifacts are cleaned up by deleting logs in '/home/bomgar/log/bt-secrets.log' to evade detection.

## Impact

Successful exploitation grants attackers full administrative control over the BeyondTrust Remote Support appliance. This exposure includes the potential compromise of all managed credentials, persistent backdoor access, and the ability to intercept remote support sessions, impacting the security of all downstream endpoints managed by the compromised device.

## Recommendation

* Apply the security patches provided by BeyondTrust for CVE-2026-102764 immediately.
* Monitor for the creation of files with SUID permissions in /usr/bin/ or other non-standard directories.
* Audit logs for execution of the '/ns/sbin/bt-secrets' utility, particularly with arguments like 'get' or 'vault'.
* Monitor for the creation of files within the '/home/bomgar/sbin/post_boot.d' directory.
* Deploy the provided Sigma rules to detect the SAWFLY webshell traffic and SUID manipulation.
