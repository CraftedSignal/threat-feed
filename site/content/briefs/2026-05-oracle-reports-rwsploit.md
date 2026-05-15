---
title: Public Exploit Available for Oracle Reports CVE-2012-3152 and CVE-2012-3153
slug: 2026-05-oracle-reports-rwsploit
description: A public exploit, rwsploit, has been released targeting CVE-2012-3152 and CVE-2012-3153 in Oracle Reports Server versions below 11g, enabling unauthenticated file read, SSRF, and JSP shell upload.
date: "2026-05-15T22:01:21Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:oracle:fusion_middleware:11.1.1.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:fusion_middleware:11.1.1.6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:fusion_middleware:11.1.2.0:*:*:*:*:*:*:*
tags:
  - oracle
  - reports server
  - cve-2012-3152
  - cve-2012-3153
  - lfi
  - ssrf
  - jsp shell
  - rwsploit
vendors:
  - Oracle
products:
  - Reports Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2012-3153
    epss: 0.91205
references:
  - https://sploitus.com/exploit?id=3F90DA9C-C8D3-574C-B1CC-AEF89D90FF98&utm_source=rss&utm_medium=rss
  - CVE-2012-3152
  - CVE-2012-3153
rules:
  - title: Detect Oracle Reports rwservlet Path Traversal Attempt
    description: Detects CVE-2012-3152 exploitation — Attempts to access sensitive files via the rwservlet endpoint with path traversal
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Oracle Reports SSRF via rwservlet JOBTYPE rwurl
    description: Detects CVE-2012-3153 exploitation — SSRF attempts via rwservlet with JOBTYPE=rwurl and suspicious URLPARAMETER
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A public exploit, named rwsploit, has been released targeting CVE-2012-3152 and CVE-2012-3153 affecting Oracle Reports Server versions prior to 11g. The tool automates the detection and exploitation of vulnerable Oracle Reports Server instances, enabling unauthenticated file reads (LFI), Server-Side Request Forgery (SSRF), and JSP shell uploads. The rwsploit tool, written in Python, allows operators to scan single IPs, CIDR ranges, or lists of targets, and includes features to detect the underlying operating system to tailor LFI payloads. The availability of this exploit significantly increases the risk to unpatched Oracle Reports Server instances, as exploitation can now be easily performed by attackers.

## Attack Chain

1.  Attacker identifies vulnerable Oracle Reports Server instances using reconnaissance techniques such as Shodan, Censys, or Google dorks.
2.  The attacker uses rwsploit to scan the identified targets, specifying the target IP or CIDR range and desired ports.
3.  Rwsploit attempts to detect the Oracle Reports Server version by sending requests to `/reports/rwservlet`.
4.  The tool exploits CVE-2012-3152 to perform unauthenticated Local File Inclusion (LFI) attacks to read sensitive files. The OS is detected first to run the matching payloads.
5.  Rwsploit exploits CVE-2012-3153 to perform Server-Side Request Forgery (SSRF) attacks using the `rwservlet?JOBTYPE=rwurl&URLPARAMETER=` endpoint, verifying the success with webhook.site.
6.  If desired, the attacker uploads a JSP shell using the `--shell` option, first reading the webroot path using `showenv` and then writing the shell via `rwservlet?report=xyzzy&destype=file&desname=&JOBTYPE=rwurl&URLPARAMETER=`.
7.  Rwsploit verifies the JSP shell upload by checking the shell URL for an HTTP 200 response.
8.  The attacker uses the uploaded JSP shell to gain remote code execution on the target server.

## Impact

Successful exploitation allows attackers to read sensitive files, perform SSRF attacks, and ultimately gain remote code execution on the Oracle Reports Server. This can lead to data theft, system compromise, and further lateral movement within the network. The tool's automated nature means that attackers can efficiently scan and exploit large numbers of vulnerable systems, potentially impacting numerous organizations running older versions of Oracle Reports Server.

## Recommendation

*   Apply the vendor-provided patches for CVE-2012-3152 and CVE-2012-3153 to mitigate the vulnerabilities in Oracle Reports Server versions below 11g.
*   Deploy the Sigma rule "Detect Oracle Reports rwservlet Path Traversal Attempt" to identify attempts to exploit CVE-2012-3152 in web server logs.
*   Monitor network traffic for unusual outbound connections from Oracle Reports Server, especially to external URLs, to detect potential SSRF attacks related to CVE-2012-3153.
*   Use the provided Shodan, FOFA, Censys, and Google dorks to identify potentially vulnerable Oracle Reports Server instances within your network or exposed to the internet.
*   Enable Sysmon process creation logging to facilitate detection of suspicious processes spawned from the Oracle Reports Server process.
