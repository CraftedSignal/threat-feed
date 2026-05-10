---
title: Multiple Vulnerabilities in Atlassian Products
slug: 2026-04-atlassian-vulns
description: Multiple vulnerabilities in Atlassian Bamboo, Bitbucket, Confluence, and Jira allow attackers to execute arbitrary code, bypass security measures, manipulate data, disclose information, or perform cross-site scripting attacks.
date: "2026-04-28T08:31:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - atlassian
  - vulnerability
  - code-execution
  - xss
vendors:
  - Atlassian
products:
  - Bamboo
  - Bitbucket
  - Confluence
  - Jira
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
cves:
  - id: CVE-2026-21571
    cvss: 9.4
  - id: CVE-2022-1471
    cvss: 9.8
  - id: CVE-2024-47875
    cvss: 10.0
  - id: CVE-2021-31597
    cvss: 9.4
  - id: CVE-2026-25547
    cvss: 9.2
  - id: CVE-2026-33871
    cvss: 8.7
  - id: CVE-2026-24880
    cvss: 7.5
  - id: CVE-2026-33870
    cvss: 7.5
  - id: CVE-2026-24734
    cvss: 7.5
  - id: CVE-2026-25639
    cvss: 7.5
  - id: CVE-2024-45801
    cvss: 7.3
  - id: CVE-2022-25927
    cvss: 7.5
  - id: CVE-2026-23950
    cvss: 8.8
  - id: CVE-2026-29063
    cvss: 8.7
  - id: CVE-2026-23745
    cvss: 8.2
  - id: CVE-2026-24842
    cvss: 8.2
  - id: CVE-2026-31802
    cvss: 8.2
  - id: CVE-2026-22029
    cvss: 8.0
  - id: CVE-2026-26960
    cvss: 7.1
  - id: CVE-2025-66020
    cvss: 7.5
  - id: CVE-2024-29371
    cvss: 7.5
  - id: CVE-2023-48631
    cvss: 7.5
  - id: CVE-2025-48734
    cvss: 8.8
  - id: CVE-2021-0341
    cvss: 7.5
  - id: CVE-2023-1370
    cvss: 7.5
  - id: CVE-2023-3635
    cvss: 7.5
references:
  - https://confluence.atlassian.com/security/security-bulletin-april-21-2026-1770913890.html
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1229
rules:
  - title: Detect Suspicious HTTP Requests to Atlassian Products
    description: Detects suspicious HTTP requests potentially related to vulnerability exploitation attempts against Atlassian products based on URI patterns and HTTP methods.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Atlassian Product Spawning Shell Processes
    description: Detects Atlassian products spawning shell processes, which can indicate command execution after vulnerability exploitation.
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

Atlassian's April 21, 2026 security bulletin patches 26 CVEs across Bamboo, Bitbucket, Confluence, Jira, and Jira Service Management — including four rated Critical. The highest-severity issue is CVE-2024-47875 (CVSS 10.0), a mutation XSS vulnerability in the dompurify dependency affecting Jira and JSM. CVE-2022-1471 (CVSS 9.8) enables remote code execution via a YAML deserialization flaw in org.yaml:snakeyaml, affecting Confluence, Jira, and JSM. CVE-2026-21571 (CVSS 9.4) allows OS command injection in Bamboo Data Center and Server. CVE-2021-31597 (CVSS 9.4) is a man-in-the-middle vulnerability in Jira Service Management via the xmlhttprequest dependency. The remaining 22 vulnerabilities are rated High and cover DoS (netty, axios, okio, brace-expansion, snakeyaml), HTTP request smuggling (Tomcat, Netty), path traversal and file inclusion (node-tar), and additional XSS issues. All vulnerabilities stem from third-party dependencies bundled in Atlassian products.

## Attack Chain

1.  **Initial Access:** An attacker identifies a vulnerable Atlassian product instance (Bamboo, Bitbucket, Confluence, or Jira) accessible over the network.
2.  **Vulnerability Exploitation:** The attacker leverages an unknown vulnerability to inject malicious code into the application, possibly through a crafted HTTP request.
3.  **Code Execution:** The injected code executes within the context of the Atlassian application, allowing the attacker to run arbitrary commands on the server.
4.  **Privilege Escalation:** The attacker leverages the initial code execution to escalate privileges, potentially gaining root or administrator access.
5.  **Defense Evasion:** The attacker attempts to disable security logging or other monitoring mechanisms to avoid detection.
6.  **Data Manipulation/Exfiltration:** The attacker accesses sensitive data stored within the Atlassian application or connected databases, manipulating or exfiltrating it for malicious purposes.
7.  **Lateral Movement:** Using compromised credentials or established footholds, the attacker moves laterally to other systems within the network.
8.  **Impact:** The attacker achieves their final objective, such as deploying ransomware, stealing intellectual property, or disrupting business operations.

## Impact

Successful exploitation of these vulnerabilities could result in significant damage, including complete compromise of Atlassian servers, data breaches, and disruption of critical business processes. The number of potential victims is substantial, as these Atlassian products are widely used across various industries. The impact ranges from data loss and financial damage to reputational harm and legal liabilities.

## Recommendation

*   Deploy the Sigma rules provided in this brief to detect potential exploitation attempts targeting Atlassian products.
*   Monitor web server logs for suspicious activity, especially HTTP requests targeting Atlassian applications, to detect potential vulnerability exploitation.
*   Enable and review audit logs within Atlassian products (Bamboo, Bitbucket, Confluence, Jira) for suspicious activity.
*   Implement network segmentation to limit the potential impact of a successful breach originating from a compromised Atlassian server.
