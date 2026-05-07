---
title: Ivanti EPMM Authenticated Remote Code Execution Vulnerability Exploited
slug: 2026-05-ivanti-eppm-rce
description: CVE-2026-6973, an authenticated remote code execution vulnerability in Ivanti Endpoint Manager Mobile (EPMM), is being actively exploited, potentially leading to data breaches and system compromise.
date: "2026-05-07T14:54:45Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:ivanti:endpoint_manager_mobile:*:*:*:*:*:*:*:*
tags:
  - ivanti
  - eppm
  - rce
  - vulnerability
  - exploitation
vendors:
  - Ivanti
products:
  - Endpoint Manager Mobile (EPMM)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: System Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-1340
    cvss: 9.8
    epss: 0.70832
references:
  - https://ccb.belgium.be/advisories/warning-authenticated-remote-code-execution-vulnerability-ivanti-eppm-exploited-patch
  - https://forums.ivanti.com/s/article/May-2026-Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-Multiple-CVEs
rules:
  - title: Detect Suspicious HTTP Requests to Ivanti EPMM
    description: Detects suspicious HTTP requests to Ivanti EPMM server potentially related to CVE-2026-6973 exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect administrative access from uncommon user agent
    description: Detects administrative web access to Ivanti EPMM from uncommon user agent strings.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1071.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Ivanti has released security updates to address multiple vulnerabilities in Ivanti Endpoint Manager Mobile (EPMM). The most critical vulnerability, CVE-2026-6973, is an improper input validation issue that allows an authenticated attacker with administrative access to execute arbitrary code remotely. Ivanti is aware of a limited number of customers being actively exploited via CVE-2026-6973. Successful exploitation could lead to data breaches, system compromise, and operational downtime. This vulnerability, along with CVE-2026-5786, CVE-2026-5787, CVE-2026-5788 and CVE-2026-7821, affects Ivanti EPMM versions before 12.6.1.1, 12.7.0.1, and 12.8.0.1. It is believed that administrative credentials used to exploit CVE-2026-6973 were obtained through previous exploitation of CVE-2026-1340.

## Attack Chain

1. Initial compromise via CVE-2026-1340, allowing attackers to gain administrative credentials.
2. Attacker authenticates to the Ivanti EPMM administrative interface.
3. Exploitation of CVE-2026-6973 through crafted requests to the server.
4. Improper input validation allows the attacker to inject malicious code.
5. The injected code is executed within the context of the EPMM server.
6. Attacker gains remote code execution on the EPMM server.
7. Attacker leverages the compromised server to access sensitive data.
8. Exfiltration of sensitive data and potential deployment of malware.

## Impact

Successful exploitation of CVE-2026-6973 can lead to data breaches, system compromise, and operational downtime. A limited number of customers have reportedly been affected. The compromised EPMM server can be used as a pivot point to access other systems within the network, potentially impacting the confidentiality, integrity, and availability of critical business operations. Other vulnerabilities such as CVE-2026-5787 allow impersonation of Sentry hosts and obtaining valid CA-signed client certificates.

## Recommendation

*   Apply the security updates provided by Ivanti to patch CVE-2026-6973, CVE-2026-5786, CVE-2026-5787, CVE-2026-5788 and CVE-2026-7821 in Ivanti EPMM versions before 12.6.1.1, 12.7.0.1, and 12.8.0.1.
*   Review accounts with administrative rights on Ivanti EPMM and rotate credentials where necessary, as recommended by the vendor.
*   Monitor web server logs for suspicious activity indicative of CVE-2026-6973 exploitation. Deploy the provided Sigma rule to detect potential exploitation attempts.
*   Investigate and remediate any potential compromises resulting from the exploitation of CVE-2026-1340, if present, as a potential source of compromised credentials.
