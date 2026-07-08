---
title: Joomla Page Builder CK Arbitrary File Upload (EDB-52626)
slug: 2026-07-joomla-page-builder-ck-upload
description: A public exploit has been released for an arbitrary file upload vulnerability in Joomla Page Builder CK version 3.5.10, which allows an unauthenticated attacker to upload malicious files to the server, potentially leading to remote code execution and full system compromise.
date: "2026-07-08T13:32:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - arbitrary-file-upload
  - joomla
  - remote-code-execution
vendors:
  - Joomla
products:
  - Joomla Page Builder CK 3.5.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public webapps exploit has been published on Exploit-DB for Joomla Page Builder CK 3.5.10, demonstrating a Arbitrary File Upload vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker uploads arbitrary files to the server, potentially leading to further compromise [remote code execution].
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The attacker uploads arbitrary files to the server, potentially leading to further compromise [by leaving a persistent webshell].
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52626
---

A publicly available exploit (EDB-52626) has been published on Exploit-DB demonstrating an arbitrary file upload vulnerability within Joomla Page Builder CK version 3.5.10. This critical flaw allows an unauthenticated attacker to upload files of any type, including web shells, to a vulnerable Joomla instance. The presence of a functional public exploit significantly escalates the risk, making affected systems prime targets for immediate compromise. This type of vulnerability can lead to remote code execution (RCE), enabling attackers to gain full control over the compromised web server, access sensitive data, or use the server as a platform for further attacks.

## Attack Chain

1. **Initial Access**: An unauthenticated attacker identifies a Joomla website running Page Builder CK 3.5.10 or earlier.
2. **Vulnerability Exploitation**: The attacker crafts a malicious HTTP POST request targeting the vulnerable file upload endpoint of Page Builder CK, bypassing file type and content validation.
3. **Malicious File Upload**: The attacker uploads a malicious file, typically a PHP web shell (e.g., `shell.php` or `image.jpg.php`), to a publicly accessible directory on the Joomla server.
4. **Web Shell Execution**: The attacker navigates to the URL of the uploaded web shell through a web browser or a command-line tool.
5. **Remote Code Execution**: The web shell executes with the privileges of the web server, allowing the attacker to run arbitrary commands on the underlying operating system.
6. **Post-Exploitation**: The attacker uses the web shell to establish persistence, exfiltrate data, pivot to other internal systems, or deploy additional malware like ransomware or crypto-miners.

## Impact

The successful exploitation of this arbitrary file upload vulnerability can lead to severe consequences. Attackers can gain complete control over the compromised Joomla website and the underlying server. This includes unauthorized access to sensitive information stored on the server, website defacement, disruption of services, and the use of the server as a launchpad for further attacks within the organization's network. The availability of a public exploit increases the likelihood of widespread exploitation against unpatched Joomla installations globally, potentially impacting businesses across all sectors.

## Recommendation

* Immediately update Joomla Page Builder CK to a patched version to remediate EDB-52626.
* Deploy a Web Application Firewall (WAF) to detect and block malicious file uploads and web shell execution attempts, focusing on `webserver` logs.
* Regularly review `webserver` logs for suspicious HTTP POST requests attempting to upload unusual file types or access newly created executable files.
* Implement file integrity monitoring on web server directories to detect unauthorized creation or modification of files, particularly those with executable extensions.
