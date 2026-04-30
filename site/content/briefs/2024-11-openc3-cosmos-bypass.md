---
title: OpenC3 COSMOS Script Runner Permissions Bypass
slug: 2024-11-openc3-cosmos-bypass
description: The OpenC3 COSMOS Script Runner widget allows authenticated users to bypass API permissions checks and execute administrative actions by running specially crafted Python and Ruby scripts, leading to data manipulation and privilege escalation.
date: "2024-11-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openc3
  - cosmos
  - script-runner
  - permissions-bypass
  - privilege-escalation
vendors:
  - rubygems
products:
  - openc3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2wvh-87g2-89hr
rules:
  - title: Detect Script Runner Accessing Redis Credentials via Env
    description: Detects a Ruby script executed via the Script Runner attempting to extract Redis credentials by querying environment variables.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Script Runner Writing to Redis Database
    description: Detects a Python or Ruby script executed via the Script Runner attempting to write data to the Redis database.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The openc3-COSMOS-script-runner-api container includes a Script Runner widget that enables users to execute Python and Ruby scripts. A vulnerability exists where users with script execution privileges can bypass API permission checks due to shared networking among Docker containers. This bypass allows unauthorized administrative actions such as reading and modifying data within the Redis database, which can lead to the exposure of sensitive credentials and alteration of COSMOS settings. Attackers can also read and write to the buckets service, affecting configuration, logs, and plugins. The vulnerability affects versions prior to 7.0.0-rc3 of the rubygems/openc3 package, posing a significant risk to data integrity and system security. Any authenticated user with script execution capabilities can exploit this flaw to connect to any service within the Docker network, escalating their privileges and gaining control over critical system components.

## Attack Chain

1. An attacker logs into the OpenC3 COSMOS platform with a valid, non-administrative user account that has access to the Script Runner widget.
2. The attacker crafts a Ruby script to extract Redis credentials (username, password, hostname, port) by querying the environment variables within the `openc3-COSMOS-script-runner-api` container using a command like `puts \`env | grep redis\``.
3. The attacker executes the Ruby script within the Script Runner widget, successfully retrieving the Redis credentials, which are then displayed in the script's output.
4. The attacker crafts a Python script using the obtained Redis credentials to connect to the Redis database. The script is designed to create a new entry or modify an existing one. For example, `r.hset('openc3__settings_hacked','store_url',json.dumps(setting_data))`
5. The attacker executes the Python script within the Script Runner widget, successfully adding or modifying data in the Redis database, bypassing normal permission controls.
6. The attacker leverages the ability to write to the buckets service to modify critical system configuration files, such as the plugin store URL, by uploading a malicious file via a Python or Ruby script.
7. The attacker verifies the changes by using `redis-cli` to confirm the new data was added to the Redis database, or by observing the altered behavior of the system due to the modified configuration files.
8. The attacker gains complete control over the OpenC3 COSMOS environment by exploiting modified settings, potentially leading to data exfiltration, service disruption, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability allows unauthorized data disclosure and manipulation within the OpenC3 COSMOS environment. An attacker can access sensitive information such as Redis credentials, modify system settings, and alter configuration files, leading to privilege escalation. The number of affected installations is currently unknown, but the vulnerability poses a significant risk to organizations using OpenC3 COSMOS, potentially resulting in complete system compromise and loss of data integrity. The vulnerability allows unauthorized access to data and functionality typically restricted to administrators, bypassing intended security controls.

## Recommendation

*   Upgrade the `rubygems/openc3` package to version 7.0.0-rc3 or later to remediate the vulnerability (reference: rubygems/openc3 v7.0.0-rc3).
*   Implement network segmentation to isolate the `openc3-COSMOS-script-runner-api` container from other critical services like Redis, limiting the blast radius of potential attacks.
*   Deploy the Sigma rule to detect the execution of suspicious scripts within the Script Runner widget that attempt to access Redis or modify configuration files.
*   Monitor process creation events within the `openc3-COSMOS-script-runner-api` container for commands such as `env | grep redis` or any calls to `redis-cli` which is abnormal behavior, and create alerts (reference: process_creation log source).
