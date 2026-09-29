---
title: Multiple Vulnerabilities in Apache Airflow Providers
slug: 2026-09-apache-airflow-vulnerabilities
description: Multiple vulnerabilities in various Apache Airflow providers allow attackers to perform file manipulation, SQL injection, information disclosure, and security bypasses.
date: "2026-09-29T16:17:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*
  - cpe:2.3:a:alf:alf:*:*:*:*:*:*:*:*
  - cpe:2.3:a:restsharp:restsharp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - apache-airflow
  - pipeline-security
vendors:
  - Apache Software Foundation
products:
  - Apache Airflow (various provider packages)
cves:
  - id: CVE-2024-45300
    cvss: 7.5
    epss: 0.0042
  - id: CVE-2024-45301
    cvss: 5.3
    epss: 0.0029
  - id: CVE-2024-45302
    cvss: 6.1
    epss: 0.00316
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3630
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade Apache Airflow to 2.0-M5 or later
      owner: DevOps
      due: 48h
      evidence: Source reporting of multiple vulnerabilities requiring patch.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Airflow to 2.0-M5 or later
      owner: DevOps
      addresses: CVE-2024-45300, CVE-2024-45301, CVE-2024-45302
      evidence: Vendor-recommended remediation path.
---

The BSI has reported multiple vulnerabilities affecting various Apache Airflow provider packages. These security flaws allow remote attackers to manipulate files, execute SQL injection attacks, disclose sensitive information, or bypass established security controls. The issues affect the Apache Airflow ecosystem, specifically impacting the provider components that extend Airflow's functionality to various third-party services. Given that Apache Airflow is frequently used to orchestrate complex data pipelines and infrastructure workflows, successful exploitation of these vulnerabilities could lead to significant data integrity loss or unauthorized access to sensitive data processed within these pipelines. Defenders should prioritize auditing their Airflow environment dependencies and upgrading to the latest versions of the affected providers as released by the Apache Software Foundation.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized data exfiltration, modification of critical pipeline workflows, or full system compromise if Airflow-managed credentials are exposed. These flaws represent a high risk to organizations that rely on Apache Airflow for sensitive data orchestration and automated infrastructure management.

## Recommendation

* Review all currently deployed Apache Airflow provider packages and update to the latest versions provided by the Apache Software Foundation to address CVE-2024-45300, CVE-2024-45301, and CVE-2024-45302.
* Audit access logs for unauthorized access to the Airflow web interface or API endpoints that interact with the vulnerable provider plugins.
* Monitor for anomalous database queries or unexpected file modifications originating from the Airflow service account.
