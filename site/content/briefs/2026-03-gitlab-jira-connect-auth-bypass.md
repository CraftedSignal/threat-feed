---
title: GitLab Jira Connect Authentication Bypass Vulnerability (CVE-2026-2370)
slug: 2026-03-gitlab-jira-connect-auth-bypass
description: GitLab CE/EE versions 14.3 before 18.8.7, 18.9 before 18.9.3, and 18.10 before 18.10.1 are vulnerable to improper authorization checks in Jira Connect installations, allowing an authenticated user with minimal workspace permissions to obtain installation credentials and impersonate the GitLab application.
date: "2026-03-30T00:16:01Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - gitlab
  - jira
  - authentication
  - authorization
  - cve-2026-2370
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2370
  - https://about.gitlab.com/releases/2026/03/25/patch-release-gitlab-18-10-1-released/
  - https://gitlab.com/gitlab-org/gitlab/-/work_items/589635
  - https://hackerone.com/reports/3522829
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Jira Connect Activity
    description: Detects potential exploitation attempts related to Jira Connect by monitoring for unusual requests to Jira Connect endpoints.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Credential Access via Jira Connect
    description: Detects potential unauthorized access to credentials related to the Jira Connect integration by monitoring authentication logs for unusual activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - authentication
      - linux
rules_count: 2
---

GitLab has addressed a critical vulnerability, CVE-2026-2370, affecting GitLab CE/EE installations with Jira Connect enabled.  This vulnerability impacts versions 14.3 up to 18.8.7, 18.9 before 18.9.3, and 18.10 before 18.10.1. The vulnerability stems from improper authorization checks, which enable an authenticated user with minimal workspace permissions within Jira to potentially obtain GitLab installation credentials. This, in turn, allows the attacker to impersonate the GitLab application…
