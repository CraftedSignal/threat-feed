---
title: Kibana Fleet Plugin Privilege Escalation via CVE-2026-4498
slug: 2026-04-kibana-fleet-privesc
description: CVE-2026-4498 allows an authenticated Kibana user with Fleet sub-feature privileges to read index data beyond their direct Elasticsearch RBAC scope due to improper privilege handling in debug route handlers.
date: "2026-04-08T17:21:24Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

CVE-2026-4498 is a privilege escalation vulnerability affecting the Fleet plugin in Kibana. Specifically, the debug route handlers within the Fleet plugin do not properly restrict access, allowing an authenticated Kibana user with Fleet sub-feature privileges (such as agents, agent policies, and settings management) to read index data beyond their intended Elasticsearch RBAC scope. This is a weakness related to Execution with Unnecessary Privileges (CWE-250). The vulnerability was disclosed in Elastic's security update ESA-2026-21, associated with Kibana versions 8.9.3, 9.2.8, and 8.19.1. This vulnerability can lead to unauthorized data access within the Elasticsearch cluster.

## Attack Chain

1. An attacker gains access to Kibana as an authenticated user.
2. The attacker obtains Fleet sub-feature privileges (agents, policies, settings).
3. The attacker crafts a malicious request to the vulnerable debug route handler.
4. The debug route handler improperly processes the request without proper RBAC enforcement.
5. The attacker leverages the exposed debug route to read index data.
6. The attacker accesses Elasticsearch indices beyond the intended scope of their privileges.
7. The attacker gains unauthorized access to sensitive information contained within the Elasticsearch indices.

## Impact

Successful exploitation of CVE-2026-4498 allows an attacker to bypass Elasticsearch Role-Based Access Control (RBAC) and read sensitive index data that they should not have access to. The number of potentially affected Kibana instances is unknown, but all instances running vulnerable versions with the Fleet plugin enabled and accessible to users with Fleet sub-feature privileges are at risk. The specific impact depends on the nature of the data stored in the Elasticsearch indices exposed by the vulnerability.

## Recommendation

*   Upgrade Kibana to a patched version (8.9.3, 9.2.8, 8.19.1 or later) as recommended in Elastic's security advisory ESA-2026-21 to remediate CVE-2026-4498.
*   Review and restrict Fleet sub-feature privileges to only those users who require them to limit the potential attack surface.
*   Deploy the Sigma rule `Kibana Fleet Plugin Debug Route Access` to monitor for suspicious access patterns to the debug routes within the Fleet plugin.
