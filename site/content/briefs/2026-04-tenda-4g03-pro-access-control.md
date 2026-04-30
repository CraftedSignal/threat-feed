---
title: Tenda 4G03 Pro Improper Access Control Vulnerability (CVE-2026-5526)
slug: 2026-04-tenda-4g03-pro-access-control
description: CVE-2026-5526 describes an improper access control vulnerability in the Tenda 4G03 Pro router's /bin/httpd file, allowing remote attackers to potentially gain unauthorized access.
date: "2026-04-04T23:16:44Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5526
  - tenda
  - router
  - access-control
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5526
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5526
  - https://vuldb.com/vuln/355279
  - https://vuldb.com/vuln/355279/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Suspicious HTTP Request to Tenda /bin/httpd
    description: Detects suspicious HTTP requests targeting the /bin/httpd file on Tenda routers, potentially indicating exploitation attempts related to CVE-2026-5526.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unusual Process Spawning from Web Server on Tenda Router
    description: Detects unusual processes spawned from the web server process, potentially indicating command execution after exploiting CVE-2026-5526 on Tenda routers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A security vulnerability, identified as CVE-2026-5526, affects the Tenda 4G03 Pro router, specifically versions up to 1.0/1.1/04.03.01.53/192.168.0.1. The flaw resides within an unspecified function of the `/bin/httpd` file, leading to improper access controls. A remote attacker could exploit this vulnerability, potentially gaining unauthorized access to the device. Publicly available exploits exist, increasing the risk of exploitation. This issue was reported on April 4, 2026, and poses a significant threat due to the ease of remote exploitation.

## Attack Chain

1.  Attacker identifies a Tenda 4G03 Pro router with a publicly accessible web interface.
2.  The attacker crafts a malicious HTTP request targeting the `/bin/httpd` file.
3.  The malicious request exploits the improper access control vulnerability (CVE-2026-5526).
4.  The router's `/bin/httpd` process improperly handles the request, bypassing access controls.
5.  The attacker gains unauthorized access to sensitive functionalities of the router.
6.  The attacker modifies router configurations, such as DNS settings or firewall rules.
7.  The attacker could potentially use the compromised router as a pivot point for further network attacks.

## Impact

Successful exploitation of CVE-2026-5526 could allow attackers to remotely compromise Tenda 4G03 Pro routers. This can lead to unauthorized access to the device's configuration, modification of settings, or use of the router as a stepping stone for further attacks within the network. Given the availability of public exploits, unpatched devices are at significant risk. While the exact number of affected devices is unknown, the widespread use of Tenda routers makes this a potentially significant issue.

## Recommendation

*   Monitor web server logs for suspicious requests targeting `/bin/httpd` using the provided Sigma rule.
*   Apply available firmware updates or patches from Tenda to address CVE-2026-5526 as soon as they are released.
*   Implement network segmentation to limit the impact of a compromised router.
*   Enforce strong password policies for router administration to prevent unauthorized access.
*   Review and update firewall rules to restrict access to the router's web interface from untrusted networks.
*   Deploy the provided Sigma rule to detect suspicious process execution originating from the web server process.
