---
title: Unrestricted File Upload Vulnerability in Rongzhitong Visual Integrated Command and Dispatch Platform
slug: 2026-08-rongzhitong-upload
description: An unauthenticated remote code execution vulnerability (CVE-2026-18969) exists in the Rongzhitong Visual Integrated Command and Dispatch Platform due to an unrestricted file upload flaw in the /dm/dispatch/userinfo/upload endpoint.
date: "2026-08-06T01:21:18Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Rongzhitong
products:
  - Visual Integrated Command and Dispatch Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can exploit this flaw by manipulating the 'File' argument to upload arbitrary files to the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Performing a manipulation of the argument File results in unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-18969
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18969
  - https://vuldb.com/vuln/386260
rules:
  - title: Detects CVE-2026-18969 Exploitation - Unrestricted File Upload
    description: Detects potential exploitation attempts by monitoring POST requests to the vulnerable upload endpoint in the Rongzhitong platform.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect POST activity on the upload endpoint.
      owner: Detection Engineering
      due: 24h
      evidence: Source identifies /dm/dispatch/userinfo/upload as the vulnerable function.
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to the platform upload endpoint.
      owner: IT Operations
      addresses: CVE-2026-18969
      evidence: Vulnerability is remotely exploitable.
---

CVE-2026-18969 is a high-severity security vulnerability affecting the Rongzhitong Visual Integrated Command and Dispatch Platform versions up to 20260617. The flaw resides in the handling of the 'File' argument within the `/dm/dispatch/userinfo/upload` function. Due to improper access control and insufficient validation of uploaded files, an unauthenticated remote attacker can upload arbitrary files to the server. This vulnerability allows for the potential execution of malicious code, leading to system compromise. Publicly available exploit material for this vulnerability is documented, and the vendor has not provided a response or a patch as of the time of disclosure.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to gain unauthorized access to the affected command and dispatch platform. By uploading malicious files (such as web shells), attackers can achieve remote code execution, potentially resulting in full system takeover, exfiltration of sensitive command data, and disruption of critical dispatch services. Given the nature of command and dispatch systems, the potential for operational impact is significant.

## Recommendation

Detection engineering teams should focus on identifying unauthorized attempts to interact with the identified upload endpoint. 
- Deploy the provided Sigma rule to monitor for suspicious POST requests to the vulnerable upload URI. 
- Inspect web server access logs for requests to `/dm/dispatch/userinfo/upload` that do not originate from authorized administrative workflows or that exhibit unusual user-agent strings. 
- Restrict network access to the management and dispatch platform interfaces to only trusted IP ranges via internal firewalls or VPNs to mitigate remote exploitation risks.
