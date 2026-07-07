---
title: Open Babel MOPAC Parser Out-of-Bounds Write Vulnerability (CVE-2022-46294)
slug: 2026-07-open-babel-mopac-oob-write
description: A memory-safety vulnerability (CVE-2022-46294) in Open Babel's MOPAC input parser allows an out-of-bounds write into the `translationVectors[]` array when reading more than three Tv atoms from a crafted MOPAC input file, which can lead to application crash or arbitrary code execution upon victim processing the file.
date: "2026-07-03T12:47:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - memory-corruption
  - out-of-bounds-write
  - cve
  - library-vulnerability
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious MOPAC input file
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A memory-safety vulnerability in Open Babel's MOPAC input parser allowed an out-of-bounds write... Triggering this vulnerability requires the victim to open a malicious MOPAC input file
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Impairment
    evidence: can lead to memory corruption, causing the application using Open Babel to crash, resulting in a denial of service.
    confidence_band: high
cves:
  - id: CVE-2022-46294
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-mjmg-352j-f456
  - https://github.com/openbabel/openbabel/commit/40e85213
  - https://nvd.nist.gov/vuln/detail/CVE-2022-46294
---

Open Babel, a C++ library and command-line tool for chemistry file format manipulation, is affected by CVE-2022-46294, a high-severity memory-safety vulnerability. Discovered and reported by Cisco TALOS, this flaw exists in the MOPAC IN reader component. Specifically, a crafted MOPAC input file containing more than three 'Tv' (translation-vector) atoms can lead to an out-of-bounds write in the `translationVectors[]` array. This vulnerability affects all Open Babel versions up to and including 3.1.1. Exploitation requires a victim to open such a malicious file using the `obabel` CLI tool, the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, R, Perl, C#, PHP). The library is widely adopted, shipped by various Linux distributions, and often embedded in services that process chemical data, making it a critical concern for defenders. The vulnerability was patched in version 3.2.0, released on 2026-05-26, with the fix available in commit `40e85213`.

## Attack Chain

1.  Attacker crafts a malicious MOPAC input file containing more than three 'Tv' (translation-vector) atoms specifically designed to trigger an out-of-bounds write vulnerability (CVE-2022-46294).
2.  Attacker delivers the malicious MOPAC file to a target system or user, potentially via email attachments, malicious websites, or untrusted file shares.
3.  A user or automated process on the target system opens or attempts to process the malicious MOPAC file using the `obabel` command-line tool, the `OBConversion` API, or any of Open Babel's language bindings (e.g., Python `pybel`).
4.  Open Babel's MOPAC IN reader component attempts to parse the malformed input file, specifically the section containing the 'Tv' atoms.
5.  During parsing, the reader attempts to store more translation vectors than the fixed-size `translationVectors[]` array can hold, resulting in an out-of-bounds write operation past the allocated memory.
6.  This out-of-bounds write corrupts adjacent memory, potentially leading to application crash, denial of service, or, under specific conditions, arbitrary code execution.
7.  If arbitrary code execution is successfully achieved, the attacker gains control over the compromised process running Open Babel, which can be leveraged for further system compromise, data exfiltration, or installation of additional malware.

## Impact

The successful exploitation of CVE-2022-46294 can lead to memory corruption, causing the application using Open Babel to crash, resulting in a denial of service. In more severe scenarios, it could enable arbitrary code execution within the context of the affected application, allowing an attacker to compromise the system. Open Babel is a foundational library in chemistry and materials science, widely shipped by Linux distributions and integrated into various services for processing untrusted chemical data. Organizations that parse untrusted MOPAC files using vulnerable versions of Open Babel are at risk of system instability, data breaches, or complete system takeover if arbitrary code execution is achieved.

## Recommendation

*   Patch CVE-2022-46294 immediately by upgrading all affected installations of Open Babel to version 3.2.0 or higher.
