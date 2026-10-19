---
title: Unauthenticated Local File Inclusion in Oracle PeopleSoft Enterprise
slug: 2026-10-oracle-peoplesoft-lfi
description: CVE-2023-22047 allows unauthenticated attackers to perform arbitrary file reads via the wsrp-url parameter in Oracle PeopleSoft Enterprise PeopleTools.
date: "2026-10-19T17:18:55Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:oracle:peoplesoft_enterprise:8.59:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:peoplesoft_enterprise:8.60:*:*:*:*:*:*:*
tags:
  - cve-2023-22047
  - lfi
  - peoplesoft
  - vulnerability
vendors:
  - Oracle
products:
  - PeopleSoft Enterprise PeopleTools (8.59, 8.60)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2023-22047 is a critical unauthenticated Local File Inclusion (LFI) vulnerability discovered in Oracle PeopleSoft Enterprise PeopleTools.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This exploit allows an attacker to read arbitrary files from the target server without any authentication.
    confidence_band: high
cves:
  - id: CVE-2023-22047
    cvss: 7.5
    epss: 0.7698
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XTERROR-CVE-2023-22047-ORACLE-PEOPLESOFT-LFI
rules:
  - title: Detects CVE-2023-22047 Exploitation - Unauthenticated LFI via /RP
    description: Detects attempts to exploit CVE-2023-22047 by checking for the wsrp-url parameter in requests to the /RP endpoint containing common traversal or sensitive file patterns.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all internet-facing Oracle PeopleSoft instances and verify patch status for CVE-2023-22047
      owner: IT Operations
      due: 24h
      evidence: Publicly available exploit for critical unauthenticated LFI
  hunt_leads:
    - lead: Inspect web logs for attempts to access /RP with wsrp-url containing path traversal sequences or system file references
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes wsrp-url parameter exploitation vector
  mitigation_plan:
    - priority: immediate
      action: Apply security patches provided by Oracle to mitigate CVE-2023-22047
      owner: IT Operations
      addresses: CVE-2023-22047
      evidence: Critical vulnerability with public exploit
---

CVE-2023-22047 is a critical, unauthenticated Local File Inclusion (LFI) vulnerability affecting Oracle PeopleSoft Enterprise PeopleTools versions 8.59 and 8.60. The vulnerability stems from improper input validation within the Updates Environment Management component, specifically the /RP endpoint. An attacker can exploit this via the wsrp-url query parameter to read arbitrary files from the underlying server filesystem. Successful exploitation requires no authentication and enables the theft of sensitive information, including database credentials, WebLogic administrative credentials, system configuration files, environment variables, and password hashes. Public proof-of-concept exploit code is available, heightening the risk of exploitation.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Oracle PeopleSoft Enterprise instances.
2. Attacker crafts a malicious HTTP GET request targeting the /RP endpoint.
3. The request includes a crafted wsrp-url parameter containing the path to a sensitive file (e.g., /etc/passwd or application configuration files).
4. The PeopleSoft PeopleTools application fails to validate the parameter, interpreting the input as a file system path.
5. The application processes the request and accesses the file on the server filesystem.
6. The server returns the contents of the requested file in the HTTP response body to the attacker.
7. Attacker parses the returned data to extract credentials, hashes, or configuration secrets to facilitate further system compromise.

## Impact

Successful exploitation allows unauthenticated attackers to read any file on the server accessible by the service account. This frequently results in full system compromise via the acquisition of database and administrative credentials, potentially leading to unauthorized data exfiltration or lateral movement within the enterprise environment.

## Recommendation

1. Patch Oracle PeopleSoft Enterprise PeopleTools by upgrading to a secured version as specified by Oracle security advisories for CVE-2023-22047.
2. Deploy the provided Sigma rule to monitor for suspicious GET requests containing path traversal sequences or sensitive file paths in the wsrp-url parameter.
3. Implement network-level access controls to restrict access to the /RP endpoint to only authorized internal IP ranges.
4. Review web server and application logs for anomalous requests to the /RP path containing the wsrp-url parameter.
