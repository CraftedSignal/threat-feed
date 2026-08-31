---
title: Denial of Service Vulnerabilities in RHEL pipewire and dbus-broker
slug: 2026-08-rhel-dos-vulnerabilities
description: Multiple vulnerabilities in the pipewire and dbus-broker components of Red Hat Enterprise Linux allow an attacker to trigger a Denial of Service condition through system instability or service disruption.
date: "2026-08-31T11:57:33Z"
lastmod: "2026-08-31T11:58:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cyberchimps:responsive_addons:*:*:*:*:*:wordpress:*:*
vendors:
  - Red Hat
products:
  - Enterprise Linux
  - xmlrpc-c
affected_os:
  - Red Hat Enterprise Linux
  - RHEL
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker can utilize several vulnerabilities in Red Hat Enterprise Linux to perform a Denial of Service attack.
    confidence_band: high
cves:
  - id: CVE-2024-5222
    cvss: 6.4
    epss: 0.00315
  - id: CVE-2024-5223
    cvss: 6.4
    epss: 0.00326
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3095
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3078
  - https://nvd.nist.gov/vuln/detail/CVE-2023-34440
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade RHEL components to the latest versions containing patches for CVE-2024-5222 and CVE-2024-5223.
      owner: IT Operations
      addresses: CVE-2024-5222, CVE-2024-5223
      evidence: Source advisory recommends addressing identified vulnerabilities.
updates:
  - at: "2026-08-31T11:58:53Z"
    level: L1
    summary: added coverage for Enterprise Linux +1 products
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3078
---

The German Federal Office for Information Security (BSI) has released an advisory regarding multiple vulnerabilities in Red Hat Enterprise Linux (RHEL). These vulnerabilities specifically affect the 'pipewire' multimedia framework and the 'dbus-broker' message bus implementation. An attacker can leverage these flaws to induce a Denial of Service (DoS) state, potentially resulting in system instability or the crash of critical background services. This impact is significant for production environments relying on these components for inter-process communication or audio-visual processing. Defenders should prioritize updating affected systems to the latest security releases provided by Red Hat to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities leads to a Denial of Service (DoS) condition, which can cause service disruption or full system instability. The scope of targeting includes RHEL environments where pipewire and dbus-broker are active. If an attack succeeds, critical services relying on D-Bus or multimedia processing may become unresponsive, requiring manual intervention or a system reboot to restore normal operations.

## Recommendation

Prioritize the application of security updates for RHEL systems to patch CVE-2024-5222 and CVE-2024-5223. IT Operations teams should monitor for unexpected crashes or service restarts of the 'pipewire' or 'dbus-broker' binaries as potential indicators of exploitation attempts or instability.
