---
title: X.Org X11 Denial of Service Vulnerability
slug: 2026-08-xorg-dos
description: A vulnerability in X.Org X11 (CVE-2023-6478) allows a remote, authenticated attacker to trigger a Denial of Service condition through resource exhaustion.
date: "2026-08-13T12:41:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:x.org:x_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:x.org:xwayland:*:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:9.2:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*
  - cpe:2.3:a:tigervnc:tigervnc:-:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
vendors:
  - X.Org Foundation
products:
  - X.Org X11
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in X.Org X11 ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2023-6478
    cvss: 7.6
    epss: 0.01631
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0572
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Patch CVE-2023-6478
      owner: IT Operations
      addresses: CVE-2023-6478
      evidence: Source advisory indicates vulnerability requires patch remediation.
---

The X.Org Foundation has identified a security vulnerability in X.Org X11, tracked as CVE-2023-6478. The flaw allows a remote, authenticated attacker to induce a Denial of Service (DoS) state on a target system. By leveraging authenticated access, an attacker can exploit internal handling mechanisms within the X11 server to cause resource exhaustion or service disruption. This vulnerability poses a risk to environments where untrusted users possess authenticated access to the X11 display environment. Defenders should prioritize updating X.Org X11 packages to versions that incorporate the upstream patches for this issue.

## Impact

Successful exploitation results in the interruption of the X11 server, rendering the graphical display interface unavailable to the user. This impacts systems running X.Org X11 across Linux and macOS distributions, potentially affecting workstation stability or availability in multi-user environments.

## Recommendation

- Patch CVE-2023-6478 by upgrading the X.Org X11 server packages to the vendor-provided secure versions.
- Audit user permissions for X11 server access to ensure only authorized entities can establish authenticated sessions.
