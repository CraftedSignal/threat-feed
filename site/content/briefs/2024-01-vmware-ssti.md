---
title: VMware Server-Side Template Injection Attempt (CVE-2022-22954)
slug: 2024-01-vmware-ssti
description: An attacker attempts to exploit CVE-2022-22954, a server-side template injection vulnerability in VMware Workspace ONE Access and Identity Manager, by sending a crafted HTTP GET request containing malicious parameters to achieve remote code execution.
date: "2024-01-03T18:23:00Z"
lastmod: "2026-07-08T10:02:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vmware
  - ssti
  - cve-2022-22954
  - template-injection
vendors:
  - VMware
products:
  - Identity Manager
  - Workspace ONE Access
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-138b
  - https://github.com/wvu/metasploit-framework/blob/master/modules/exploits/linux/http/vmware_workspace_one_access_cve_2022_22954.rb
  - https://github.com/sherlocksecurity/VMware-CVE-2022-22954
  - https://www.vmware.com/security/advisories/VMSA-2022-0011.html
  - https://attackerkb.com/topics/BDXyTqY1ld/cve-2022-22954/rapid7-analysis
  - https://twitter.com/wvuuuuuuuuuuuuu/status/1519476924757778433
  - https://sploitus.com/exploit?id=555C3224-9482-5B98-BCBB-E11172E89770&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=555C3224-9482-5B98-BCBB-E11172E89770
  - type: command
    value: cat /etc/passwd
  - type: hash_custom
    value: "-1250474341"
  - type: hash_custom
    value: "-713727389"
  - type: hash_custom
    value: "-1987733375"
  - type: hash_custom
    value: "1459735704"
  - type: hash_custom
    value: "198112565"
ioc_counts:
  command: 1
  hash_custom: 5
  url: 1
rules:
  - title: Detect VMware CVE-2022-22954 Exploitation Attempts
    description: Detects attempts to exploit CVE-2022-22954, a server-side template injection vulnerability in VMware Workspace ONE Access and Identity Manager via HTTP GET requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect VMware CVE-2022-22954 Post-Exploitation Webshell
    description: Detects potential webshell creation as a result of CVE-2022-22954 exploitation by looking for file creation events in common web directories
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-07-08T10:02:45Z"
    level: L1
    summary: OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=555C3224-9482-5B98-BCBB-E11172E89770&utm_source=rss&utm_medium=rss
---

This threat brief addresses potential exploitation attempts targeting CVE-2022-22954, a server-side template injection vulnerability affecting VMware Workspace ONE Access (Access) and Identity Manager (vIDM). This vulnerability allows a remote attacker to execute arbitrary code on the server. The attack is initiated through malicious HTTP GET requests containing specific parameters designed to exploit the template injection flaw. This activity is significant because successful exploitation can lead to complete system compromise, unauthorized access, and the execution of arbitrary commands, making it critical for defenders to identify and mitigate these attempts. The vulnerability was disclosed in early 2022, and proof-of-concept exploits are publicly available, increasing the risk of widespread exploitation attempts.

## Attack Chain

1. The attacker identifies a vulnerable VMware Access or vIDM instance.
2. The attacker crafts a malicious HTTP GET request targeting a specific endpoint (potentially involving `deviceudid`).
3. The malicious GET request includes payload strings such as `freemarker.template.utility.ObjectConstructor` or `java.lang.ProcessBuilder` within the URL to trigger template injection.
4. The vulnerable application processes the crafted request without proper sanitization, interpreting the payload as a template instruction.
5. The template engine executes the injected code, allowing the attacker to execute arbitrary commands on the server.
6. The attacker leverages the initial code execution to establish persistence, potentially by writing a backdoor to disk.
7. The attacker escalates privileges to gain root or SYSTEM access.
8. The attacker moves laterally within the network, compromising other systems and exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2022-22954 can lead to complete compromise of the affected VMware Access or vIDM server. This includes unauthorized access to sensitive data, the ability to execute arbitrary commands, and the potential for lateral movement within the network. Organizations using vulnerable versions of VMware products are at risk of data breaches, service disruption, and reputational damage. Public exploits have been developed, increasing the likelihood of widespread attacks.

## Recommendation

*   Deploy the Sigma rule `Detect VMware CVE-2022-22954 Exploitation Attempts` to your SIEM to identify malicious HTTP GET requests (logsource: webserver, product: linux).
*   Investigate any alerts generated by the Sigma rule, focusing on systems accessing the affected VMware instances.
*   Apply the official VMware patch for CVE-2022-22954 immediately to remediate the vulnerability (reference: https://www.vmware.com/security/advisories/VMSA-2022-0011.html).
*   Monitor web server logs for unusual URL patterns containing `deviceudid` in combination with Java-related keywords, even if the Sigma rule does not trigger (logsource: webserver, product: linux).
*   Implement network segmentation to limit the impact of a successful compromise.
