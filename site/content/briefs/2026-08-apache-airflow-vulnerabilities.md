---
title: Multiple Vulnerabilities in Apache Airflow Providers
slug: 2026-08-apache-airflow-vulnerabilities
description: Apache Airflow is affected by multiple vulnerabilities, specifically CVE-2024-48792 and CVE-2024-48793, which allow a remote, authenticated attacker to perform unauthorized information disclosure.
date: "2026-08-11T10:28:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - apache-airflow
  - information-disclosure
vendors:
  - Apache
products:
  - Airflow
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A remote, authenticated attacker can exploit multiple vulnerabilities in Apache Airflow to disclose information.
    confidence_band: high
cves:
  - id: CVE-2024-48792
    cvss: 7.5
    epss: 0.00491
  - id: CVE-2024-48793
    cvss: 5.9
    epss: 0.00301
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2733
  - https://nvd.nist.gov/vuln/detail/CVE-2024-48792
  - https://nvd.nist.gov/vuln/detail/CVE-2024-48793
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit Apache Airflow provider versions
      owner: IT Operations
      due: 48h
      evidence: Source advisory states vulnerabilities in Apache Airflow Providers.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Airflow to patched versions
      owner: IT Operations
      addresses: CVE-2024-48792, CVE-2024-48793
      evidence: Remediation via vendor updates
---

Apache Airflow has been identified as vulnerable to multiple security issues, specifically tracked as CVE-2024-48792 and CVE-2024-48793. These vulnerabilities allow a remote, authenticated attacker to successfully execute unauthorized information disclosure within an Airflow environment. The vulnerabilities reside within the Airflow provider packages, which are commonly utilized for integrating Airflow with various cloud and third-party services. Defenders should prioritize auditing access logs and user permission configurations for Airflow instances, ensuring that the principle of least privilege is applied to authenticated users to mitigate the impact of potential exploitation attempts. Organizations should review their current version of Apache Airflow and any installed provider packages to ensure they are updated to the latest available versions released by the project to remediate these specific information disclosure flaws.

## Impact

Successful exploitation of these vulnerabilities results in unauthorized information disclosure, potentially exposing sensitive workflow data, configuration details, or connection credentials stored within the Airflow instance. This could lead to further reconnaissance or lateral movement by an attacker who has already obtained initial authentication.

## Recommendation

- Upgrade Apache Airflow and all relevant provider packages to the latest versions released by the Apache Software Foundation to remediate CVE-2024-48792 and CVE-2024-48793.
- Review and tighten access control lists for all authenticated users to limit exposure to sensitive data.
- Monitor logs for unusual or unauthorized access patterns targeting the Airflow web interface or API endpoints.
