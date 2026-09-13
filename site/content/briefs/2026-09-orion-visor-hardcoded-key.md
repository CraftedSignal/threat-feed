---
title: Hard-coded Cryptographic Key Vulnerability in Orion-visor
slug: 2026-09-orion-visor-hardcoded-key
description: Orion-visor versions 2.5.7 and earlier contain a hard-coded cryptographic key within the HostKeyServiceImpl.encryptKey function, enabling potential remote compromise of encrypted host keys.
date: "2026-09-13T11:25:14Z"
lastmod: "2026-09-13T13:25:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dromara:orion-visor:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - credential-exposure
  - webserver
vendors:
  - Dromara
products:
  - orion-visor (<= 2.5.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: Executing a manipulation can lead to hard-coded credentials, allowing remote attackers to potentially gain unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-90510
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90510
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90509
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the orion-visor administrative interface to trusted management ranges
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote exploitation
  mitigation_plan:
    - priority: immediate
      action: Monitor for vendor patches for CVE-2026-90510 and deploy immediately upon release
      owner: IT Operations
      addresses: CVE-2026-90510
      evidence: No current vendor patch available
updates:
  - at: "2026-09-13T13:25:15Z"
    level: L2
    summary: added coverage for orion-visor (<= 2.5.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90509
---

Dromara orion-visor, an asset management platform, is vulnerable to a security flaw identified as CVE-2026-90510. The vulnerability stems from the use of a hard-coded cryptographic key within the HostKeyServiceImpl.encryptKey function, located in the file orion-visor-modules/orion-visor-module-asset/orion-visor-module-asset-service/src/main/java/org/dromara/visor/module/asset/service/impl/HostKeyServiceImpl.java. 

Because the key is hard-coded into the source code, encryption for host keys is predictable, undermining the confidentiality of stored credentials. Attackers can leverage this fixed key to decrypt sensitive host keys remotely. The vulnerability was disclosed publicly following a failure by the project maintainers to address an early issue report. As of the current disclosure, no patch is available. Defenders should note that this vulnerability exposes the underlying infrastructure managed by orion-visor to significant risk, as the compromise of host keys often leads to unauthorized access to downstream systems.

## Impact

Successful exploitation allows remote attackers to compromise host key encryption, leading to the exposure of credentials used for remote server access. This could facilitate lateral movement, further unauthorized access to managed assets, and potential full system compromise for all hosts integrated with the affected orion-visor instance.

## Recommendation

Prioritize the identification and isolation of internet-facing orion-visor instances. Since no vendor patch exists, consider restricting access to the web interface to authorized management subnets only until a fix is released. Audit existing host key configurations for signs of unauthorized access or modification.
