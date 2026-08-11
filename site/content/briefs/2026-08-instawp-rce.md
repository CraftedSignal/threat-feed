---
title: 'CVE-2026-13457: Remote Code Execution in InstaWP Connect Plugin'
slug: 2026-08-instawp-rce
description: The InstaWP Connect WordPress plugin (<= 0.1.3.6) is vulnerable to remote code execution due to insecure configuration file storage and missing access controls on Apache servers with directory listing enabled.
date: "2026-08-11T21:50:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - rce
  - apache
vendors:
  - InstaWP
products:
  - InstaWP Connect (0.1.3.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Exposing the 40-character migrate_key on Apache servers with directory indexing enabled, which allows an attacker to derive the AES-256-CBC passphrase.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The InstaWP Connect – 1-click WP Staging & Migration plugin for WordPress is vulnerable to Remote Code Execution.
    confidence_band: high
cves:
  - id: CVE-2026-13457
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13457
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Disable directory indexing on all web servers hosting WordPress sites
      owner: IT Operations
      due: 24h
      evidence: Exploitation requires the target WordPress site to be hosted on Apache with directory listing enabled
  mitigation_plan:
    - priority: immediate
      action: Update InstaWP Connect plugin
      owner: IT Operations
      addresses: CVE-2026-13457
      evidence: The InstaWP Connect plugin for WordPress is vulnerable... in all versions up to, and including, 0.1.3.6
---

The InstaWP Connect plugin for WordPress, in versions up to and including 0.1.3.6, contains a critical security flaw allowing unauthenticated remote code execution. The vulnerability stems from the plugin's practice of saving migration configuration data as 'options-{migrate_key}.txt' files within the 'wp-content/instawpbackups/' directory. Crucially, the plugin fails to include 'index.php' or '.htaccess' files to prevent directory indexing. On web servers configured with 'Options +Indexes', attackers can list the contents of this directory to retrieve the 40-character 'migrate_key'. 

By obtaining this key, an attacker can derive the AES-256-CBC decryption passphrase through a predictable SHA256 transformation. This allows for the decryption of the 'options' file, revealing the API signature and database credentials. While exploitation is time-limited to the active migration window, the resulting exposure enables full database compromise and subsequent remote code execution on the underlying server.

## Attack Chain

1. Attacker identifies a target WordPress site utilizing the InstaWP Connect plugin.
2. Attacker probes for directory indexing on the server by navigating to 'wp-content/instawpbackups/'.
3. Attacker retrieves a listed 'options-{migrate_key}.txt' file from the directory index.
4. Attacker extracts the 40-character 'migrate_key' string from the file name.
5. Attacker computes the AES-256-CBC passphrase using the derived SHA256 hash of the 'migrate_key'.
6. Attacker decrypts the options file to obtain the 'api_signature' and database credentials.
7. Attacker uses the stolen API signature and database access to inject malicious code or commands into the WordPress database.
8. Attacker executes the injected code to gain full system control (Remote Code Execution).

## Impact

Successful exploitation allows unauthenticated attackers to steal database credentials and the API signature, leading to unauthorized database manipulation, persistent backdoors, and full remote code execution on the WordPress instance. This vulnerability affects any environment where the plugin is active and the web server's 'Options +Indexes' configuration is enabled.

## Recommendation

Prioritized actions for detection engineering teams:
* Audit all internet-facing web server configurations to disable directory indexing ('Options -Indexes' in Apache).
* Deploy web server log monitoring to detect requests targeting the '/wp-content/instawpbackups/' directory path.
* Update the InstaWP Connect plugin to the latest secure version immediately.
* Implement file integrity monitoring on the 'wp-content/instawpbackups/' path to alert on unauthorized file enumeration or access.
