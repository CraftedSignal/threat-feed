---
title: Kibana Fleet Plugin Privilege Escalation via CVE-2026-4498
slug: 2026-04-kibana-fleet-privesc
description: CVE-2026-4498 allows an authenticated Kibana user with Fleet sub-feature privileges to read index data beyond their direct Elasticsearch RBAC scope due to improper privilege handling in debug route handlers.
date: "2026-04-08T17:21:24Z"
severities:
  - medium
tags:
  - cve
  - privilege-escalation
  - kibana
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4498
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4498
  - https://discuss.elastic.co/t/kibana-8-19-14-9-2-8-9-3-3-security-update-esa-2026-21/385811
ioc_counts:
  email: 1
rules:
  - title: Kibana Fleet Plugin Debug Route Access
    description: Detects access to the Kibana Fleet plugin debug routes, which may indicate exploitation of CVE-2026-4498.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Kibana Fleet Plugin Unauthorized Index Access
    description: Detects unauthorized access to Elasticsearch indices via Kibana Fleet plugin, potentially indicating CVE-2026-4498 exploitation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4498 is a privilege escalation vulnerability affecting the Fleet plugin in Kibana. Specifically, the debug route handlers within the Fleet plugin do not properly restrict access, allowing an authenticated Kibana user with Fleet sub-feature privileges (such as agents, agent policies, and settings management) to read index data beyond their intended Elasticsearch RBAC scope. This is a weakness related to Execution with Unnecessary Privileges (CWE-250). The vulnerability was disclosed in…
