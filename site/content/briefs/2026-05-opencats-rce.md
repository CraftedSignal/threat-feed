---
title: OpenCATS 0.9.4 Remote Code Execution Vulnerability (CVE-2021-47936)
slug: 2026-05-opencats-rce
description: OpenCATS 0.9.4 is vulnerable to remote code execution (CVE-2021-47936) allowing unauthenticated attackers to execute arbitrary commands by uploading malicious PHP files disguised as resume attachments through the careers job application endpoint, leading to potential system compromise.
date: "2026-05-10T13:19:13Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - CVE-2021-47936
  - rce
  - opencats
  - vulnerability
vendors:
  - OpenCATS
products:
  - OpenCATS 0.9.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2021-47936
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47936
  - https://github.com/opencats/OpenCATS
  - https://www.exploit-db.com/exploits/50585
  - https://www.opencats.org/
  - https://www.vulncheck.com/advisories/opencats-remote-code-execution-via-resume-upload
rules:
  - title: Detect OpenCATS RCE via Resume Upload
    description: Detects CVE-2021-47936 exploitation — HTTP POST requests to the uploads directory with a PHP file extension, indicating a potential RCE attempt in OpenCATS 0.9.4
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect OpenCATS Suspicious Upload Directory Access
    description: Detects access to the OpenCATS uploads directory which could indicate post-exploitation activity after a file upload vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

OpenCATS 0.9.4 contains a remote code execution vulnerability, identified as CVE-2021-47936, that allows unauthenticated attackers to execute arbitrary commands. The vulnerability stems from the application's handling of resume attachments uploaded through the careers/job application endpoint. By disguising malicious PHP files as legitimate resumes, attackers can bypass upload restrictions and inject executable code into the server's upload directory. Successful exploitation allows attackers to execute system commands via POST requests to the uploaded PHP file, potentially leading to full system compromise. This vulnerability poses a significant risk to organizations using OpenCATS 0.9.4, as it requires no authentication and can be exploited remotely.

## Attack Chain

1.  An unauthenticated attacker accesses the careers/job application endpoint of an OpenCATS 0.9.4 instance.
2.  The attacker crafts a malicious PHP file containing the desired payload (e.g., a reverse shell or command execution).
3.  The attacker disguises the PHP file as a resume attachment (e.g., by changing the file extension or embedding it within a PDF).
4.  The attacker uploads the malicious file through the job application form.
5.  The OpenCATS application saves the uploaded file to the server's upload directory (location varies based on configuration).
6.  The attacker identifies the location and filename of the uploaded file.
7.  The attacker sends a POST request to the uploaded PHP file, including the system commands to be executed in the request body.
8.  The server executes the commands specified in the POST request, enabling the attacker to achieve remote code execution.

## Impact

Successful exploitation of CVE-2021-47936 allows unauthenticated attackers to execute arbitrary commands on the OpenCATS server. This can lead to complete system compromise, data theft, and denial of service. Given the nature of OpenCATS, a recruitment applicant tracking system, the impact includes exposure of sensitive applicant data. Since the exploit is unauthenticated, any OpenCATS 0.9.4 instance exposed to the internet is at risk.

## Recommendation

*   Apply available patches or upgrade to a supported version of OpenCATS to remediate CVE-2021-47936.
*   Implement strict file type validation on all file upload endpoints, blocking the upload of executable files (e.g., PHP, ASP, JSP).
*   Monitor web server logs for suspicious POST requests targeting files in the upload directory as detected by the Sigma rule "Detect OpenCATS RCE via Resume Upload".
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
