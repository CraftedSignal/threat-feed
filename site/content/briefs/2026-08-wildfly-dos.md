---
title: Denial of Service Vulnerability in Red Hat WildFly and JBoss EAP
slug: 2026-08-wildfly-dos
description: A vulnerability in Red Hat WildFly and JBoss Enterprise Application Platform allows a remote, unauthenticated attacker to trigger a denial-of-service condition.
date: "2026-08-13T12:52:38Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:samsung:exynos_980_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_850_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1080_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1280_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1380_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1330_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1480_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_w920_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_w930_firmware:-:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - WildFly
  - JBoss Enterprise Application Platform
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Anonymer Angreifer kann eine Schwachstelle in Red Hat WildFly und Red Hat JBoss Enterprise Application Platform ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-27365
    cvss: 4.4
    epss: 0.00174
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2802
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27365
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch Red Hat WildFly and JBoss EAP instances
      owner: IT Operations
      addresses: CVE-2024-27365
      evidence: Vendor advisory confirms vulnerability and necessity of updates.
---

A vulnerability has been identified in Red Hat WildFly and Red Hat JBoss Enterprise Application Platform (EAP) that allows a remote, unauthenticated attacker to cause a denial-of-service (DoS) condition. The vulnerability, tracked as CVE-2024-27365, impacts the availability of the application server by enabling an attacker to overwhelm system resources or trigger an application crash. Because these servers are typically internet-facing components of an enterprise architecture, this vulnerability poses a risk to service uptime. Defenders should prioritize patching or applying vendor-recommended configurations to limit exposure of management interfaces and application endpoints to untrusted networks.

## Impact

Successful exploitation results in the disruption of service for Red Hat WildFly or JBoss EAP instances. This can impact mission-critical business applications, internal services, and customer-facing portals that rely on these platforms.

## Recommendation

* Apply the security patches provided by Red Hat for all affected JBoss EAP and WildFly deployments.
* Audit network perimeter defenses to ensure that management interfaces of application servers are not exposed to the public internet.
* Monitor application server logs for frequent crash events or unexpected service restarts that may indicate exploitation attempts.
