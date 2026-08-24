---
title: Multiple Vulnerabilities in Nvidia GPU Display Drivers
slug: 2026-08-nvidia-driver-vulnerabilities
description: Local attackers can exploit multiple vulnerabilities in Nvidia GPU display drivers to execute arbitrary code, disclose sensitive information, or trigger a denial-of-service condition.
date: "2026-08-24T15:59:02Z"
lastmod: "2026-08-24T15:59:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:nvidia:virtual_gpu:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nvidia:cloud_gaming:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nvidia:triton_inference_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:linux:*:*
vendors:
  - Nvidia
products:
  - GPU Display Driver
  - vGPU Software
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann mehrere Schwachstellen in Nvidia Treiber ausnutzen, um beliebigen Programmcode auszuführen.
    confidence_band: high
cves:
  - id: CVE-2024-0086
    cvss: 5.5
    epss: 0.0015
  - id: CVE-2024-0087
    cvss: 9
    epss: 0.1992
  - id: CVE-2024-0089
    cvss: 7.8
    epss: 0.00234
  - id: CVE-2024-0090
    cvss: 7.8
    epss: 0.00275
  - id: CVE-2024-0091
    cvss: 7.8
    epss: 0.00239
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0112
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2792
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-0202
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2532
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Deploy latest Nvidia GPU display driver updates
      owner: IT Operations
      addresses: Multiple vulnerabilities in Nvidia GPU Display Driver
      evidence: Nvidia security advisory for driver updates
updates:
  - at: "2026-08-24T15:59:26Z"
    level: L2
    summary: added CVE-2024-0086 +4
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2532
---

Nvidia has disclosed multiple security vulnerabilities affecting its GPU display driver software on both Windows and Linux platforms. These vulnerabilities are exploitable by a local attacker who has already achieved some level of access to the system. Successful exploitation allows the attacker to execute arbitrary code, manipulate files, disclose sensitive information, or cause a denial-of-service (DoS) state. These flaws represent a significant risk for systems where untrusted local users have interactive access or where secondary exploitation chains can facilitate privilege escalation from a lower-privileged user context to the kernel or system level. Defenders should prioritize patching these drivers on all systems utilizing Nvidia hardware to mitigate the potential for local privilege escalation or system instability.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise, unauthorized access to sensitive local data, or system-wide instability. Affected sectors include any environment relying on Nvidia hardware for computing, graphics, or AI workloads, particularly multi-user systems or those where local user security boundaries must be strictly maintained.

## Recommendation

Prioritize the deployment of vendor-supplied driver updates across all affected Windows and Linux endpoints and servers. Ensure that Nvidia driver update packages are integrated into the organization's patch management cycle, particularly for high-security or multi-user environments.
