---
title: Denial of Service Vulnerability in Red Hat Enterprise Linux opentelemetry-collector
slug: 2026-09-rhel-otel-dos
description: A vulnerability in the opentelemetry-collector package within Red Hat Enterprise Linux allows a remote, unauthenticated attacker to trigger a denial of service condition, potentially disrupting monitoring and telemetry data collection services.
date: "2026-09-25T14:01:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:redhat:opentelemetry-collector:*:*:*:*:*:*:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*
  - cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
vendors:
  - Red Hat
products:
  - opentelemetry-collector (< 124.0.6367.155)
affected_os:
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Red Hat Enterprise Linux im opentelemetry-collector ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-4558
    cvss: 9.6
    epss: 0.01533
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0754
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade opentelemetry-collector to 124.0.6367.155 or later
      owner: IT Operations
      addresses: CVE-2024-4558
      evidence: BSI advisory WID-SEC-2025-0754
---

A vulnerability has been identified in the opentelemetry-collector package provided within Red Hat Enterprise Linux distributions. The issue, tracked as CVE-2024-4558, allows a remote, unauthenticated attacker to cause a denial of service condition. This impact is significant for environments relying on the collector for observability and infrastructure monitoring, as successful exploitation results in the cessation of data processing and reporting. Defenders should prioritize updating the opentelemetry-collector package to the patched version provided by Red Hat to restore the stability of telemetry pipelines.

## Impact

The successful exploitation of this vulnerability results in a denial of service, rendering the opentelemetry-collector unresponsive. This causes a loss of observability data for systems monitored by the collector, potentially impacting the ability of security operations centers to ingest telemetry, logs, or metrics essential for incident detection and system performance monitoring.

## Recommendation

Prioritize patching the affected infrastructure by applying the latest security updates released by Red Hat for the opentelemetry-collector package. Verify system stability post-patching to ensure that service interruptions related to CVE-2024-4558 are resolved.
