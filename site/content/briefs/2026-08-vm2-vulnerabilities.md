---
title: Multiple Vulnerabilities in vm2 Sandbox Library
slug: 2026-08-vm2-vulnerabilities
description: The vm2 sandbox library is affected by multiple critical vulnerabilities, including remote code execution via sandbox escape, which allow attackers to manipulate data, disclose information, or execute arbitrary code.
date: "2026-08-17T18:42:58Z"
lastmod: "2026-08-17T18:45:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ethyca:fides:*:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_9820_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_980_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_850_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1080_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2100_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2200_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1280_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1380_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1330_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_modem_5123_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_modem_5300_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_auto_t5123_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:a:opswat:metadefender_kiosk:*:*:*:*:*:*:*:*
tags:
  - sandbox-escape
  - nodejs
  - code-execution
  - cve-2026-47686
products:
  - vm2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit multiple vulnerabilities in vm2 to execute arbitrary program code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: An attacker can traverse that reference to achieve arbitrary command execution on the host.
    confidence_band: high
cves:
  - id: CVE-2023-37480
    cvss: 2.7
    epss: 0.00685
  - id: CVE-2023-37367
    cvss: 5.3
    epss: 0.00441
  - id: CVE-2023-36657
    cvss: 9.8
    epss: 0.00567
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2865
  - https://nvd.nist.gov/vuln/detail/CVE-2023-37480
  - https://nvd.nist.gov/vuln/detail/CVE-2023-37367
  - https://nvd.nist.gov/vuln/detail/CVE-2023-36657
  - https://github.com/advisories/GHSA-m283-3h24-438v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47686
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory applications using the vm2 library and prioritize patching
      owner: Application Security
      due: 48h
      evidence: Source confirms multiple critical vulnerabilities in vm2
  mitigation_plan:
    - priority: immediate
      action: Upgrade vm2 to a patched version or replace library
      owner: IT Operations
      addresses: CVE-2023-37480, CVE-2023-37367, CVE-2023-36657
      evidence: Source reporting of critical security flaws
updates:
  - at: "2026-08-17T18:45:50Z"
    level: L2
    summary: added coverage for vm2
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-m283-3h24-438v
---

The vm2 sandbox library is subject to multiple critical vulnerabilities, tracked as CVE-2023-37480, CVE-2023-37367, and CVE-2023-36657. These vulnerabilities arise from flaws within the sandbox implementation that permit an attacker to escape the restricted environment. By bypassing the sandbox constraints, an unauthenticated attacker can execute arbitrary code on the host system, manipulate sensitive data, perform denial of service attacks, or disclose confidential information. Because vm2 is frequently used to execute untrusted JavaScript code in server-side environments, these vulnerabilities pose a significant risk to applications relying on this library for process isolation. Defenders should verify if their internal applications or third-party dependencies utilize vulnerable versions of vm2 and prioritize upgrading to secure versions or migrating to alternative sandboxing solutions.

## Impact

Successful exploitation of these vulnerabilities leads to full sandbox escape, granting the attacker the ability to execute code with the privileges of the Node.js process. This may result in total system compromise, exfiltration of application secrets, and disruption of critical business services through denial of service. The scope of impact is widespread across any server-side application using the affected library versions for code evaluation.

## Recommendation

- Identify all applications within the environment utilizing the vm2 library via software composition analysis (SCA) or dependency auditing tools.
- Patch or update affected applications to the latest secure version of vm2 immediately.
- In environments where patching is not immediately feasible, evaluate the implementation of secondary security controls such as containerization or restricted service accounts to limit the blast radius of a potential sandbox escape.
- Review application logs for unusual patterns or child process spawning initiated by the Node.js runtime environment associated with the vm2 library.
