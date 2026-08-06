---
title: 'CVE-2026-5855: Out-of-Bounds Read Vulnerability in Contiki-NG LwM2M Parser'
slug: 2026-08-contiki-ng-oob-read
description: Contiki-NG's LwM2M TLV parser contains an out-of-bounds read vulnerability that allows unauthenticated attackers to disclose heap memory contents via crafted CoAP WRITE requests.
date: "2026-08-06T23:30:49Z"
lastmod: "2026-08-06T23:30:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Contiki-NG
products:
  - Contiki-NG
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A crafted CoAP WRITE to any LwM2M endpoint whose final TLV supplies exactly one byte triggers up to five out-of-bounds reads of heap memory adjacent to the CoAP input buffer, disclosing memory contents (including key material and peer addresses).
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: On builds with RESOLV_CONF_SUPPORTS_MDNS enabled, any peer on the local segment can trigger the read unauthenticated via a multicast UDP 5353 packet.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1595.003
    technique_name: 'Active Scanning: Wordlist Scanning'
    evidence: An attacker can craft malicious DNS packets with an inflated nquestions count to trigger memory reads beyond the UDP packet buffer.
    confidence_band: high
cves:
  - id: CVE-2026-5855
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5855
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5856
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Restrict access to LwM2M endpoints to trusted management VLANs to mitigate lack of authentication in NoSec mode.
      owner: IT Operations
      due: 24h
      evidence: In LwM2M NoSec mode, the default for constrained devices, no authentication is required.
  mitigation_plan:
    - priority: immediate
      action: Patch os/services/lwm2m/lwm2m-tlv.c in the Contiki-NG codebase.
      owner: Security Engineering
      addresses: CVE-2026-5855
      evidence: Contiki-NG's LwM2M TLV parser lwm2m_tlv_read() in os/services/lwm2m/lwm2m-tlv.c ignores its caller-supplied buffer length argument.
updates:
  - at: "2026-08-06T23:30:57Z"
    level: L1
    summary: added coverage for Contiki-NG
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-5856
---

CVE-2026-5855 describes a critical out-of-bounds read vulnerability within the Contiki-NG LwM2M implementation, specifically affecting the `lwm2m_tlv_read()` function located in `os/services/lwm2m/lwm2m-tlv.c`. The parser fails to respect the caller-supplied buffer length argument and performs reads up to six bytes beyond the intended heap buffer bounds without appropriate validation. 

When operating in LwM2M NoSec mode, which is the default configuration for many constrained devices, this vulnerability can be triggered by an unauthenticated attacker sending a crafted CoAP WRITE request. The vulnerability is triggered when the final TLV field in the request contains exactly one byte. Successful exploitation allows for the disclosure of sensitive heap memory, potentially exposing cryptographic key material, peer addresses, and other internal state information. Furthermore, the resulting corruption of the `tlv_len` field can lead to downstream processing logic failures or further memory corruption.

## Impact

Successful exploitation of CVE-2026-5855 enables unauthorized information disclosure from the device's heap memory. Given the context of constrained IoT devices running Contiki-NG, this may result in the compromise of static cryptographic keys or network topology metadata. The vulnerability is particularly dangerous because it does not require authentication in default NoSec deployments, increasing the likelihood of remote exploitation against exposed IoT infrastructure.

## Recommendation

- Audit network edge traffic for CoAP WRITE requests targeting constrained devices running Contiki-NG.
- Implement strict ingress filtering to restrict CoAP traffic to authorized network segments, as NoSec LwM2M is inherently vulnerable to unauthenticated access.
- Apply the vendor-provided patch for `os/services/lwm2m/lwm2m-tlv.c` to enforce correct buffer bounds checking in the `lwm2m_tlv_read` function.
- Monitor for unusual CoAP traffic patterns, specifically malformed WRITE payloads characterized by single-byte final TLVs that may indicate exploitation attempts.
