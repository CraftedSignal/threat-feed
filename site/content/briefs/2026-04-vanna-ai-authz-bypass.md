---
title: vanna-ai vanna Improper Authorization Vulnerability (CVE-2026-6977)
slug: 2026-04-vanna-ai-authz-bypass
description: An improper authorization vulnerability (CVE-2026-6977) exists in vanna-ai vanna up to version 2.0.2 due to manipulation of an unknown function within the Legacy Flask API, potentially allowing remote attackers to bypass intended access restrictions.
date: "2026-04-25T11:16:19Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - vulnerability
  - authorization
  - web application
vendors:
  - vanna-ai
products:
  - vanna
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Drives
cves:
  - id: CVE-2026-6977
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6977
  - https://github.com/yidaozhongqing/York/issues/2
  - https://vuldb.com/submit/795331
  - https://vuldb.com/vuln/359520
  - https://vuldb.com/vuln/359520/cti
rules:
  - title: Detect Potential vanna-ai vanna Unauthorized Access Attempt
    description: Detects suspicious HTTP requests potentially exploiting the CVE-2026-6977 vulnerability in vanna-ai vanna, focusing on unusual methods or parameters targeting the Legacy Flask API.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect vanna-ai vanna request to github exploit
    description: Detects web requests to a known exploit URL for vanna-ai vanna
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A security vulnerability, identified as CVE-2026-6977, has been discovered in vanna-ai vanna versions up to 2.0.2. The vulnerability resides within an unspecified function of the Legacy Flask API component. Successful exploitation of this flaw leads to improper authorization, potentially granting unauthorized access to sensitive resources or functionalities. The vulnerability is remotely exploitable and a proof-of-concept exploit is publicly available. The vendor was contacted but did not respond. This vulnerability poses a risk to systems utilizing the affected versions of vanna-ai vanna, as attackers could leverage it to bypass intended access controls.

## Attack Chain

1.  Attacker identifies a vulnerable vanna-ai vanna instance running version 2.0.2 or earlier.
2.  Attacker crafts a malicious HTTP request targeting the Legacy Flask API. The specific endpoint and parameters involved are not defined in the source material.
3.  The crafted request exploits the improper authorization vulnerability (CVE-2026-6977) within the Legacy Flask API.
4.  Due to the improper authorization flaw, the attacker's request bypasses the intended access controls.
5.  The vulnerable application grants the attacker unauthorized access to resources or functionalities that should be restricted.
6.  Depending on the accessed resources, the attacker may gain access to sensitive data, modify system settings, or perform other unauthorized actions.
7.  The attacker may escalate privileges or move laterally within the affected system if further vulnerabilities exist or if the compromised application has elevated permissions.

## Impact

Successful exploitation of CVE-2026-6977 allows a remote attacker to bypass authorization checks in vanna-ai vanna, potentially leading to unauthorized access to sensitive data or functionality. Given that a public exploit exists, organizations utilizing affected versions of vanna-ai vanna are at increased risk. The lack of vendor response further exacerbates the risk, as no official patch or mitigation guidance is available.

## Recommendation

*   Monitor web server logs for suspicious activity targeting the Legacy Flask API in vanna-ai vanna, using a webserver category Sigma rule focused on unusual HTTP requests.
*   Apply generic hardening and input validation techniques to mitigate the impact of potential exploits targeting web applications.
*   Investigate and validate the activity from the VulDB references provided in this brief.
