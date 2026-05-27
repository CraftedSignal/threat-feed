---
title: Pimcore CustomReports Share Bypass Vulnerability
slug: 2026-05-pimcore-report-bypass
description: Pimcore's CustomReports feature has a share bypass vulnerability due to inconsistent authorization checks between the report listing endpoint and the report detail endpoint, allowing low-privileged users to access report configurations without explicit sharing permissions.
date: "2026-05-27T22:35:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - defense-evasion
  - web-application
vendors:
  - pimcore
products:
  - Pimcore CustomReports
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-jwcc-gv4m-93x6
rules:
  - title: Detect Pimcore CustomReports Share Bypass
    description: Detects unauthorized access to Pimcore CustomReports configurations by identifying requests to the 'getAction' endpoint for reports that are not listed as accessible to the user.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
rules_count: 1
---

Pimcore's CustomReports utilizes inconsistent authorization between the report listing endpoint and the report detail endpoint. The report listing flow filters reports based on report-sharing rules, while the detail flow only checks for generic `reports` or `reports_config` permissions. As a result, a low-privileged backend user who has been granted the `reports` permission, but not explicitly granted access to a specific report, can still read that report directly by name, even if the report does not appear in the user's visible report list. The vulnerability resides within the CustomReports bundle and affects Pimcore instances where custom reports with restricted access are in use. This vulnerability allows unauthorized access to sensitive report metadata.

## Attack Chain

1. An attacker authenticates as a low-privileged backend user with the `reports` permission.
2. The attacker attempts to list available custom reports via the designated endpoint.
3. The server filters the list of reports based on sharing rules, excluding reports not explicitly shared with the user.
4. The attacker identifies a target report name through reconnaissance or other means.
5. The attacker crafts a direct request to the report detail endpoint, specifying the target report name.
6. The server checks only for generic `reports` permissions, bypassing the sharing rules enforced in the listing endpoint.
7. The server retrieves and returns the report configuration to the attacker.
8. The attacker gains unauthorized access to sensitive report metadata, including report name, data source configuration, and sharing settings.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive report metadata, including the report name, grouping information, display and icon metadata, data source configuration, column configuration, and sharing settings. This can lead to information disclosure and potentially further unauthorized actions, depending on the content of the reports. The source code suggests that other report endpoints like `data`, `chart`, `create-csv`, and `download-csv` might also be vulnerable due to similar resolution-by-name mechanisms.

## Recommendation

*   Deploy the Sigma rule `Detect Pimcore CustomReports Share Bypass` to your SIEM to identify requests to the report detail endpoint (`getAction`) for reports that are not listed as accessible to the user.
*   Review and audit all custom report sharing configurations to ensure proper access controls are in place.
*   Investigate other potentially vulnerable report endpoints, such as `data`, `chart`, `create-csv`, and `download-csv`, for similar access control bypass issues.
