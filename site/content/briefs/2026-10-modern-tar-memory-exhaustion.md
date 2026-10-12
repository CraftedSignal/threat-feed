---
title: Memory Exhaustion Vulnerability in modern-tar
slug: 2026-10-modern-tar-memory-exhaustion
description: The modern-tar library versions 0.3.5 through 0.8.5 are susceptible to a memory exhaustion denial-of-service vulnerability triggered by crafted, compressed archives.
date: "2026-10-12T22:41:39Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:modern-tar_project:modern-tar:0.3.5:*:*:*:*:*:*:*
  - cpe:2.3:a:modern-tar_project:modern-tar:0.8.5:*:*:*:*:*:*:*
products:
  - modern-tar (0.3.5-0.8.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The modern-tar library versions 0.3.5 through 0.8.5 are vulnerable to a memory exhaustion attack... leading to memory exhaustion and potential denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-109380
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109380
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications leveraging modern-tar 0.3.5-0.8.5
      owner: Application Security
      due: 72h
      evidence: CVE-2026-109380 advisory
  mitigation_plan:
    - priority: medium_term
      action: Upgrade modern-tar to a version outside the 0.3.5-0.8.5 range
      owner: IT Operations
      addresses: CVE-2026-109380
      evidence: NVD vulnerability report
---

The modern-tar library, specifically versions 0.3.5 through 0.8.5, contains a memory exhaustion vulnerability (CVE-2026-109380) that impacts applications utilizing the library to unpack archives. The vulnerability exists within the readOctal() function, which fails to correctly sanitize non-octal bytes during input parsing. An attacker can exploit this flaw by providing a maliciously crafted, optionally gzip-compressed archive to the unpackTar() function. This input causes the parser to calculate negative entry sizes, leading the process to buffer data chunks indefinitely. The resulting memory exhaustion results in a denial-of-service condition for the affected application and prevents the processing of subsequent entries in the archive. Defenders should identify applications using these versions of modern-tar and upgrade to a patched release once available to mitigate the risk of service interruption.

## Impact

Successful exploitation of this vulnerability results in an application-level denial-of-service. By inducing memory exhaustion, attackers can crash service components that handle archive processing, impacting system availability for users of the vulnerable software. The impact is primarily restricted to availability and does not typically involve code execution or unauthorized data access based on currently available information.

## Recommendation

* Identify all internal and vendor-supplied software dependencies utilizing modern-tar versions 0.3.5 through 0.8.5.
* Update identified software to a non-vulnerable version of modern-tar as soon as patches are released by the maintainers.
* Implement resource limits (ulimit or container resource quotas) on processes responsible for parsing untrusted user-supplied archives to minimize the impact of potential memory exhaustion attacks.
* Monitor application logs for unexpected process restarts or memory-related crashes associated with archive processing functionality.
