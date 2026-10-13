---
title: Resource Exhaustion Vulnerability in cbor-sync
slug: 2026-10-cbor-sync-dos
description: The cbor-sync library through version 1.0.4 is vulnerable to resource exhaustion via a crafted CBOR payload that causes uncontrolled iteration, leading to potential denial of service.
date: "2026-10-13T00:30:50Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:cbor-sync_project:cbor-sync:*:*:*:*:*:*:*:*
cves:
  - id: CVE-2020-37280
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37280
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications utilizing cbor-sync version 1.0.4 or earlier
      owner: IT Operations
      due: 48h
      evidence: Source identifies cbor-sync through 1.0.4 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Update cbor-sync to the latest available version (current patch version > 1.0.4)
      owner: IT Operations
      addresses: CVE-2020-37280
      evidence: NVD states cbor-sync through 1.0.4 is vulnerable
---

The cbor-sync library (all versions up to and including 1.0.4) contains a resource exhaustion vulnerability in the `CBOR.decode` function. The library trusts declared array and map lengths within CBOR-encoded data without verifying them against the actual remaining input size. A remote attacker can supply a small, maliciously crafted CBOR payload that specifies an extremely large array or map length. When parsed by the `CBOR.decode` function, this payload forces the application to attempt to allocate excessive memory or process billions of iterations. This behavior results in high CPU utilization and memory exhaustion, effectively causing a denial-of-service condition for the host process. This vulnerability is significant for any application that accepts untrusted CBOR input from network endpoints.

## Impact

Successful exploitation of this vulnerability results in a denial of service (DoS) for applications utilizing the affected cbor-sync library. By forcing the host process to exhaust CPU cycles and system memory, attackers can cause application crashes or non-responsiveness. This impacts services relying on CBOR for data exchange, potentially leading to widespread service unavailability if the library is used in critical API endpoints or backend message-processing components.

## Recommendation

Prioritize the update of all instances of the cbor-sync library to a version later than 1.0.4. If an immediate update is not feasible, implement strict input validation for all CBOR payloads before passing them to the `CBOR.decode` function, specifically by verifying that the length headers of arrays and maps align with the actual data present in the input buffer.
