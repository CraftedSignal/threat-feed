---
title: Denial of Service Vulnerability in libarchive
slug: 2026-09-libarchive-dos
description: A memory corruption vulnerability in libarchive (CVE-2024-20696) allows a local attacker to cause a Denial of Service condition through the processing of specially crafted archive files.
date: "2026-09-14T19:02:49Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
vendors:
  - libarchive
products:
  - libarchive
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A local attacker can exploit a vulnerability in libarchive to damage memory and induce a Denial of Service condition.
    confidence_band: high
cves:
  - id: CVE-2024-20696
    cvss: 7.3
    epss: 0.03128
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3340
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Update all software packages leveraging libarchive to the version containing the patch for CVE-2024-20696.
      owner: IT Operations
      addresses: CVE-2024-20696
      evidence: Source advisory recommends addressing the memory corruption vulnerability.
---

The BSI has reported a vulnerability in libarchive, tracked as CVE-2024-20696. This vulnerability stems from improper memory management during the processing of archive files. A local attacker can exploit this flaw by providing a specially crafted archive file to an application that utilizes an affected version of libarchive. Successful exploitation results in memory corruption, which forces the host application to terminate, leading to a Denial of Service (DoS) state. Given that libarchive is a widely used library for reading and writing various archive formats, this issue may impact numerous applications across Windows, macOS, and Linux environments. Defenders should identify applications within their environment that link against libarchive and ensure they are updated to patched versions provided by the respective maintainers.

## Impact

Successful exploitation of this vulnerability results in a Denial of Service, which can disrupt the availability of software relying on libarchive for archive processing. While the impact is limited to a DoS condition by a local attacker, the breadth of applications that include this library may lead to availability issues for critical business processes or security services that utilize archive extraction functionality.

## Recommendation

- Perform a dependency audit to identify all software and services within the infrastructure that rely on libarchive.
- Update all identified instances of libarchive to the latest version patched for CVE-2024-20696 as released by the software vendor or distribution maintainer.
- Prioritize patching for internet-facing applications or services that allow user-supplied archive file uploads.
