---
title: PHP File Creation in WordPress Plugin Directory
slug: 2026-07-php-file-creation-wordpress-plugin
description: Attackers commonly establish persistence on compromised Linux WordPress web servers by creating malicious PHP files, often web shells, within the WordPress plugin directory, enabling remote access and command execution following initial compromise of a public-facing application.
date: "2026-07-20T11:41:12Z"
lastmod: "2026-07-22T13:13:54Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:exclusiveaddons:exclusive_addons_for_elementor:*:*:*:*:*:wordpress:*:*
tags:
  - persistence
  - initial-access
  - execution
  - web-shell
  - wordpress
  - linux
  - endpoint
  - threat-detection
  - vulnerability
vendors:
  - Automattic
  - WordPress
products:
  - WordPress
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Detects the creation of a PHP file in the WordPress plugin directory, which is a common technique used by attackers to establish persistence on a compromised web server.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This activity often follows an initial compromise of a public-facing application.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers may upload a malicious PHP file and call it from a web browser to gain remote access to the server.
    confidence_band: high
cves:
  - id: CVE-2024-1234
    cvss: 6.4
    epss: 0.01593
references:
  - https://github.com/Icex0/wp2shell-poc
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_php_file_creation_in_wordpress_plugin_dir.toml
iocs:
  - type: url
    value: https://github.com/Icex0/wp2shell-poc
ioc_counts:
  url: 1
rules:
  - title: Detect PHP File Creation in WordPress Plugin Directory
    description: Detects the creation or modification of PHP files within the WordPress plugin directory, which is a common technique used by attackers to establish persistence on a compromised Linux web server via web shells.
    platform: sigma
    severity: low
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1190
      - T1505
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 1
updates:
  - at: "2026-07-22T13:13:54Z"
    level: L1
    summary: new IOCs
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_php_file_creation_in_wordpress_plugin_dir.toml
---

Threat actors frequently target WordPress installations on Linux web servers to establish persistence through the creation of malicious PHP files, typically web shells. This technique involves an initial compromise, often via a vulnerable public-facing application, followed by the upload or creation of a PHP file within the `/wp-content/plugins/` directory. Once deployed, these web shells can be accessed remotely via a web browser, allowing attackers to execute arbitrary commands, exfiltrate data, or further compromise the server and potentially the broader network. This activity is a critical indicator of post-exploitation, even if the initial access vector is unknown, and monitoring such file creations helps detect malicious activity aimed at maintaining long-term unauthorized access.

## Attack Chain

1. An attacker gains initial access to a vulnerable WordPress server, often exploiting a known vulnerability in a plugin, theme, or WordPress core (e.g., CVE-2024-1234, if applicable).
2. The attacker uses their initial access to upload or create a malicious PHP file, often a web shell, within the `/wp-content/plugins/` directory of the WordPress installation.
3. The malicious PHP file is typically disguised with a name resembling a legitimate plugin file or a common utility script to evade detection.
4. The attacker accesses the newly created web shell via a web browser, sending specially crafted HTTP requests to invoke its functionality.
5. The web shell executes the attacker's commands on the underlying Linux operating system.
6. Through the web shell, the attacker performs actions such as data exfiltration, privilege escalation, or lateral movement within the network.
7. The web shell serves as a persistent backdoor, allowing the attacker to regain access to the compromised server at will.

## Impact

Successful establishment of a PHP web shell in the WordPress plugin directory grants attackers remote code execution capabilities on the compromised Linux server. This can lead to severe consequences including, but not limited to, unauthorized access to sensitive data stored on the server, defacement of the website, use of the server for hosting malicious content (e.g., phishing pages, malware distribution), use as a C2 node, or further compromise of the internal network through lateral movement. The number of potential victims is vast, as WordPress powers a significant portion of the internet's websites, making it a frequent target for financially motivated cybercriminals and state-sponsored groups.

## Recommendation

* Deploy the Sigma rule "Detect PHP File Creation in WordPress Plugin Directory" to your SIEM and tune for your environment.
* Ensure `file_event` logging for Linux endpoints is enabled, specifically monitoring file creation and modification events, to activate the rule above.
* Regularly patch WordPress core, plugins, and themes to mitigate vulnerabilities that could lead to initial access and web shell deployment.
* Implement file integrity monitoring (FIM) for critical WordPress directories like `/wp-content/plugins/` to detect unauthorized file changes.
