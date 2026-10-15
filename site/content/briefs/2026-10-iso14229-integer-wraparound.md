---
title: Integer Wraparound Vulnerability in Driftregion iso14229
slug: 2026-10-iso14229-integer-wraparound
description: Driftregion iso14229 versions before 0.10.1 are vulnerable to an integer wraparound in Handle_0x38_RequestFileTransfer, allowing unauthenticated attackers to trigger an out-of-bounds read.
date: "2026-10-15T22:50:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:driftregion:iso14229:*:*:*:*:*:*:*:*
vendors:
  - Driftregion
products:
  - iso14229 (< 0.10.1)
cves:
  - id: CVE-2026-111282
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111282
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Driftregion iso14229 to version 0.10.1 or later
      owner: IT Operations
      addresses: CVE-2026-111282
      evidence: NVD vulnerability advisory
---

Driftregion iso14229 versions prior to 0.10.1 contain an integer wraparound vulnerability in the Handle_0x38_RequestFileTransfer function. This flaw arises during the processing of Unified Diagnostic Services (UDS) file transfer requests (SID 0x38). An unauthenticated attacker can exploit this by crafting a request with a filePathAndNameLength value set between 0xFFFC and 0xFFFF. This specific input causes an integer wraparound, which bypasses intended file path length checks and leads to an out-of-bounds memory read. Depending on the memory state, this vulnerability can be leveraged to cause a denial-of-service (crash) or the disclosure of sensitive memory contents. Defenders should focus on identifying malformed UDS SID 0x38 traffic targeting systems utilizing the iso14229 library.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to crash affected services or disclose sensitive memory contents, potentially exposing cryptographic keys or other process-specific information. This is particularly critical for industrial or automotive controllers utilizing the iso14229 library for diagnostic communication.

## Recommendation

* Upgrade the Driftregion iso14229 library to version 0.10.1 or later to implement proper bounds checking on the filePathAndNameLength field.
* Implement input validation on diagnostic gateways or firewalls to drop UDS SID 0x38 requests containing anomalous length parameters.
