---
title: Critical Vulnerabilities in GitLab GraphQL Implementation
slug: 2026-08-gitlab-graphql-vulns
description: GitLab Community and Enterprise editions are vulnerable to two GraphQL-related flaws (CVE-2026-19478 and CVE-2026-19650) that could allow unauthorized data modification or deletion.
date: "2026-08-18T13:57:53Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - GitLab
products:
  - GitLab Community Edition
  - GitLab Enterprise Edition
cves:
  - id: CVE-2026-19478
    cvss: 9.4
  - id: CVE-2026-19650
    cvss: 7.1
references:
  - https://www.ncsc.nl/alerts/ernstige-kwetsbaarheden-in-gitlab-producten-ontdekt-update-nu
  - https://advisories.ncsc.nl/2026/ncsc-2026-0303.html
rules:
  - title: Detect Potential GraphQL Exploitation Attempts in GitLab
    description: Detects potentially unauthorized access or manipulation attempts via GraphQL endpoints, which may be associated with CVE-2026-19478 or CVE-2026-19650.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch GitLab instances to version 19.2.4, 19.1.6, 19.0.8, or 18.11.11
      owner: IT Operations
      due: 24h
      evidence: GitLab has released updates that resolve these vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Identify and patch affected GitLab versions
      owner: IT Operations
      addresses: CVE-2026-19478, CVE-2026-19650
      evidence: NCSC-NL advisory and GitLab version requirements
---

The National Cyber Security Centre of the Netherlands (NCSC-NL) has issued an alert regarding two critical vulnerabilities within the GraphQL components of GitLab Community Edition (CE) and Enterprise Edition (EE). These vulnerabilities, identified as CVE-2026-19478 and CVE-2026-19650, impact versions prior to 19.2.4, 19.1.6, 19.0.8, and 18.11.11.

CVE-2026-19478, carrying a CVSS score of 9.4, specifically enables unauthorized users to modify or delete data within public projects and user profiles. CVE-2026-19650, with a CVSS score of 7.1, involves an improper processing flaw that permits unauthorized users to execute server-side modifications. Given that GitLab serves as a central platform for software development, these vulnerabilities pose a high risk of sensitive data loss, project integrity compromise, and systemic disruption of development pipelines. Defenders are urged to audit their GitLab instances and apply the patches provided by GitLab immediately.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized actors to manipulate or purge critical project data and profile information. This impacts any organization relying on GitLab for version control and CI/CD operations, potentially leading to the destruction of proprietary source code, credentials stored within project variables, and project metadata. The damage is considered high, though the NCSC characterizes the likelihood of opportunistic exploitation as medium.

## Recommendation

* Apply the security updates for GitLab versions 19.2.4, 19.1.6, 19.0.8, or 18.11.11 immediately to remediate CVE-2026-19478 and CVE-2026-19650.
* Audit web server logs for irregular POST requests targeting GraphQL endpoints (/api/graphql) originating from unauthorized user sessions.
* Consult the official NCSC-NL advisory at https://advisories.ncsc.nl/2026/ncsc-2026-0303.html for detailed mitigation and versioning guidance.
