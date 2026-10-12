---
title: Critical RCE Vulnerability in GitLab CE and EE
slug: 2026-10-gitlab-vulnerabilities
description: GitLab released security updates for 24 vulnerabilities, including a critical unauthenticated RCE via integer overflow (CVE-2026-97229) in the CI/CD regular expression compiler.
date: "2026-10-12T18:29:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - devops
vendors:
  - GitLab
products:
  - GitLab Community Edition (< 19.4.2, 19.3.4, 19.2.8)
  - GitLab Enterprise Edition (< 19.4.2, 19.3.4, 19.2.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability CVE-2026-97229, with a CVSS score of 10.0, is located in the CI/CD regular expression compiler and allows an unauthenticated attacker to execute arbitrary code on the server.
    confidence_band: high
references:
  - https://cert.europa.eu/publications/security-advisories/2026-016/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all self-managed GitLab instances to the latest patched version (19.4.2, 19.3.4, or 19.2.8)
      owner: IT Operations
      due: 24h
      evidence: CERT-EU strongly recommends upgrading self-managed GitLab CE/EE instances to a fixed version as soon as possible.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitLab instances to 19.4.2, 19.3.4, or 19.2.8
      owner: IT Operations
      addresses: CVE-2026-97229, CVE-2026-92883, CVE-2026-16301
      evidence: GitLab released versions 19.4.2, 19.3.4 and 19.2.8 ... fixing 24 security issues.
---

On 12 October 2026, GitLab issued emergency security patches to address 24 distinct vulnerabilities affecting self-managed GitLab Community Edition (CE) and Enterprise Edition (EE). The most severe issue is CVE-2026-97229 (CVSS 10.0), a critical vulnerability within the CI/CD regular expression compiler. This flaw stems from weak validation of regular expressions, resulting in an integer overflow that can be leveraged by unauthenticated attackers to achieve arbitrary code execution on the underlying server.

In addition to the remote code execution vulnerability, the patches address several other high-impact security flaws. These include CVE-2026-92883 (CVSS 8.7), a cross-site scripting (XSS) vulnerability in syntax highlighting that permits authenticated users to execute malicious JavaScript in the context of other users' browsers, and CVE-2026-16301 (CVSS 8.5), which allows unauthorized execution of pipelines on protected branches. Given the severity of CVE-2026-97229, immediate remediation is required for all internet-facing instances.

## Impact

The vulnerability CVE-2026-97229 enables unauthenticated remote code execution, which grants an attacker full control over the affected GitLab server. Successful exploitation could lead to the theft of repository source code, compromise of CI/CD pipeline secrets, and potential lateral movement into the build environment or internal network. Other vulnerabilities, such as cache poisoning and authorization bypasses, further increase the risk of credential theft and unauthorized access to protected internal resources.

## Recommendation

* Immediately upgrade all self-managed GitLab CE/EE instances to version 19.4.2, 19.3.4, or 19.2.8 to mitigate CVE-2026-97229, CVE-2026-92883, and CVE-2026-16301.
* Prioritize patching of internet-facing instances.
* Audit CI/CD configurations for anomalous regular expression patterns that may attempt to trigger the integer overflow identified in CVE-2026-97229.
