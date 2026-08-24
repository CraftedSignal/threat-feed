---
title: Heap-based Buffer Overflow in Open5GS S6a Authentication-Information-Request Handler
slug: 2026-08-open5gs-overflow
description: Open5GS 2.8.0 contains a remote heap-based buffer overflow vulnerability (CVE-2026-78156) in the S6a Authentication-Information-Request Handler that can be triggered by manipulating the Visited-PLMN-Id argument.
date: "2026-08-24T01:40:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Open5GS
products:
  - Open5GS (2.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
cves:
  - id: CVE-2026-78156
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78156
  - https://github.com/open5gs/open5gs/commit/a9c82ee0b590d76a581b0580cb46b598984e2392
  - https://github.com/open5gs/open5gs/issues/4661
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Open5GS to current release
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-78156 requires vendor patch
  mitigation_plan:
    - priority: immediate
      action: Restrict S6a network access
      owner: Security Engineering
      addresses: CVE-2026-78156
      evidence: Remote exploitation vector
---

A heap-based buffer overflow vulnerability has been identified in Open5GS version 2.8.0, specifically impacting the S6a Authentication-Information-Request Handler. The flaw exists within the `hss_ogs_diam_s6a_air_cb` function located in the file `src/hss/hss-s6a-path.c`. An attacker can remotely exploit this vulnerability by providing a specially crafted `Visited-PLMN-Id` argument to the HSS component. Successful exploitation could lead to memory corruption, potentially causing service crashes or arbitrary code execution. The vulnerability is addressed in the commit `a9c82ee0b590d76a581b0580cb46b598984e2392`. This issue is significant for operators of 5G core networks using the Open5GS framework, as it allows for unauthorized interaction with the S6a interface.

## Attack Chain

1. Attacker establishes network connectivity to the Diameter S6a interface exposed by the Open5GS HSS component.
2. Attacker initiates an Authentication-Information-Request (AIR) Diameter message.
3. Attacker crafts the `Visited-PLMN-Id` parameter in the DIAMETER message with excessive or malformed data designed to exceed allocated buffer boundaries.
4. The HSS component parses the incoming message using the vulnerable `hss_ogs_diam_s6a_air_cb` function.
5. The function copies the malicious `Visited-PLMN-Id` value into a heap-allocated buffer without adequate bounds checking.
6. Memory corruption occurs due to the heap-based buffer overflow, overwriting adjacent heap structures.
7. Attacker triggers a crash or redirects execution flow to achieve unauthorized impact.

## Impact

The vulnerability poses a high risk to the confidentiality, integrity, and availability of 5G core network infrastructure utilizing Open5GS 2.8.0. Successful exploitation of this remote buffer overflow can lead to denial-of-service via service disruption or potential remote code execution on the server hosting the HSS process, compromising core authentication services.

## Recommendation

- Immediately update Open5GS deployments to a version containing the fix for commit `a9c82ee0b590d76a581b0580cb46b598984e2392`.
- Implement network-level access control lists (ACLs) to restrict access to the Diameter S6a interface to authorized network elements only.
- Monitor logs for unusual Diameter traffic patterns or unexpected crashes of the HSS process.
- Review network configurations to ensure that the HSS component is not unnecessarily exposed to untrusted external networks.
