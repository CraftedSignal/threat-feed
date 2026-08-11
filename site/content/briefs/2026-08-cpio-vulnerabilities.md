---
title: Multiple Vulnerabilities in GNU cpio
slug: 2026-08-cpio-vulnerabilities
description: Multiple vulnerabilities in the GNU cpio utility allow unauthenticated remote attackers to bypass security controls, cause denial of service, or manipulate data during file extraction.
date: "2026-08-10T13:25:39Z"
lastmod: "2026-08-11T09:57:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - GNU
products:
  - cpio
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The advisory indicates vulnerabilities during file extraction processing, implying user or process-initiated execution.
    confidence_band: med
cves:
  - id: CVE-2026-66486
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2722
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66486
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Update cpio utility across all Linux/Unix systems
      owner: IT Operations
      addresses: cpio
      evidence: General security hygiene for utility vulnerabilities
updates:
  - at: "2026-08-11T09:57:51Z"
    level: L2
    summary: added CVE-2026-66486
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66486
---

Multiple vulnerabilities have been identified in the GNU cpio utility, a common tool used for processing archive files on Linux and Unix systems. These flaws can be triggered by a remote, unauthenticated attacker, potentially leading to security bypasses, denial of service conditions, or arbitrary data manipulation. The impact is specifically localized to the handling, extraction, and processing of cpio archives. Defenders should monitor for unexpected or unauthorized use of the cpio binary, especially when processing externally sourced archive files, as these vulnerabilities are effectively triggered through maliciously crafted archive content.

## Impact

Successful exploitation of these vulnerabilities allows for the manipulation of files during the extraction process or the consumption of system resources to achieve a denial of service. The scope of impact is limited to systems where untrusted or externally sourced cpio archives are processed. Potential damage includes unauthorized file system access or system instability.

## Recommendation

1. Inventory all systems within the environment that utilize the GNU cpio binary.
2. Prioritize patching or updating cpio to the latest version provided by the distribution vendor.
3. Implement strict input validation or sandboxing for any automated service that processes user-submitted cpio archives.
4. Review system logs for the execution of cpio involving external file sources.
