---
title: 'CVE-2026-35001: Integer Overflow in OpenS100 Bathymetric Parser'
slug: 2026-10-opens100-integer-overflow
description: An integer overflow in the OpenS100 S-102 parser allows remote attackers to trigger heap-based buffer overflows and potential arbitrary code execution via malicious HDF5 metadata.
date: "2026-10-13T02:32:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opens100:opens100:*:*:*:*:*:*:*:*
vendors:
  - OpenS100
products:
  - OpenS100 (<= daa35b)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The S-102 Bathymetric Surface parser allows remote attackers to cause a heap-based buffer overflow by opening a crafted S-102 HDF5 file with malicious grid dimension metadata.
    confidence_band: high
cves:
  - id: CVE-2026-35001
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35001
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade OpenS100 library to a version after commit daa35b
      owner: IT Operations
      due: 72h
      evidence: Source documentation identifies commit daa35b as the affected threshold.
  mitigation_plan:
    - priority: immediate
      action: Implement strict validation of S-102 HDF5 file metadata before passing to the parser
      owner: Development
      addresses: CVE-2026-35001
      evidence: The vulnerability is triggered by unvalidated multiplication of grid dimensions.
---

OpenS100 through commit daa35b is vulnerable to a heap-based buffer overflow stemming from an integer overflow in the S-102 Bathymetric Surface parser. The vulnerability exists within the S102_VG_BathymetryCoverage::Read() function. An attacker can exploit this by providing a specially crafted S-102 HDF5 file containing malicious grid dimension metadata. During the calculation of grid points, the multiplication of the numPointsLatitudinal and numPointsLongitudinal variables is performed without proper validation, leading to a 32-bit integer wraparound. This creates an undersized heap buffer, which the subsequent copy operation overflows. Depending on the environment, this vulnerability may result in an application crash (Denial of Service) or arbitrary code execution. This is particularly relevant for systems processing maritime bathymetric data, as the vulnerability is triggered upon the parsing of untrusted S-102 dataset files.

## Impact

Successful exploitation of this vulnerability in an environment processing maritime data can lead to arbitrary code execution, potentially allowing an attacker to gain control over systems utilizing the OpenS100 library. The impact is significant for maritime monitoring, hydrographic data management, or research sectors that rely on the OpenS100 framework to process S-102 standard datasets. If leveraged, an attacker could move laterally through a network, exfiltrate sensitive hydrographic data, or cause widespread service disruption via recurring application crashes.

## Recommendation

* Identify all systems utilizing the OpenS100 library by scanning for the presence of the library in compiled binaries or dependency manifests.
* Restrict the ingestion of untrusted S-102 bathymetric HDF5 files until the library is patched.
* Upgrade all instances of OpenS100 to a version beyond commit daa35b or apply the vendor-provided patch addressing the integer overflow in the S102_VG_BathymetryCoverage::Read() function.
* Implement memory protection mechanisms such as Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP) on systems processing these files to increase the difficulty of successful exploitation.
