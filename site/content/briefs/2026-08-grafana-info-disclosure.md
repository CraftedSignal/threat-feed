---
title: Grafana Improper Access Control Information Disclosure Vulnerability
slug: 2026-08-grafana-info-disclosure
description: An authenticated, remote attacker can exploit a flaw in Grafana to perform unauthorized information disclosure due to improper access control.
date: "2026-08-18T14:51:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:grafana:grafana:11.0.0:*:*:*:*:*:*:*
tags:
  - informational
  - product-news
vendors:
  - Grafana Labs
products:
  - Grafana
cves:
  - id: CVE-2024-9264
    cvss: 9.9
    epss: 0.94644
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2873
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Patch Grafana to the latest secure version provided by the vendor.
      owner: IT Operations
      addresses: CVE-2024-9264
      evidence: Source advisory recommends update to remediate information disclosure flaw.
---

The German Federal Office for Information Security (BSI) has reported a vulnerability in Grafana that allows a remote, authenticated attacker to disclose sensitive information. The flaw, tracked as CVE-2024-9264, stems from improper access control mechanisms within the application. This vulnerability enables an attacker who already possesses valid authentication credentials to access data or system information that they are not authorized to view. Because this requires an authenticated session, the primary threat involves users or compromised accounts escalating their access to read data outside their intended scope. Defenders should review access logs and internal permissions for Grafana installations to identify potential exploitation patterns or unusual data access requests by existing users.

## Impact

Successful exploitation allows unauthorized disclosure of sensitive data within the Grafana environment. This can lead to the exposure of dashboard configurations, data source connection details, or internal system metrics, depending on the scope of the affected user's session and the target resources.

## Recommendation

* Review security patches provided by Grafana Labs for all internal and cloud-hosted Grafana instances.
* Audit current user roles and permissions in the Grafana administrative console to minimize the potential impact of an account being used for unauthorized data access.
* Monitor Grafana access logs for anomalous patterns, specifically looking for high-frequency requests or attempts to access directories and API endpoints outside of the user's assigned dashboard scope.
