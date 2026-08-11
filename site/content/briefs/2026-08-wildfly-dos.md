---
title: Remote Denial of Service in Wildfly via CSIv2 GSS Token Handling
slug: 2026-08-wildfly-dos
description: An unauthenticated remote attacker can trigger a denial-of-service condition in Wildfly by sending a maliciously crafted GSS token that forces an uncontrolled memory allocation.
date: "2026-08-11T09:50:34Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - JBoss
products:
  - Wildfly
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remote unauthenticated attacker can trigger OutOfMemoryError as CSIv2Util's GSS token decoder reads an attacker-controlled length field without bounds checking.
    confidence_band: high
cves:
  - id: CVE-2026-15567
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15567
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Wildfly to remediate CVE-2026-15567
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-15567 is a remote unauthenticated DoS vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the CSIv2 interface via network ACLs
      owner: IT Operations
      addresses: CVE-2026-15567
      evidence: Vulnerability allows unauthenticated remote exploitation.
---

Wildfly contains a vulnerability (CVE-2026-15567) within the CSIv2Util component, which is responsible for handling Common Secure Interoperability version 2 (CSIv2) communications. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted GSS token to the service. The vulnerability exists because the token decoder reads an attacker-controlled length field from the incoming packet without performing adequate bounds checking. This unchecked length is subsequently used to allocate a byte array in memory. If an attacker specifies a sufficiently large value, the application will attempt to allocate excessive memory, resulting in an OutOfMemoryError and causing the application to crash or become unresponsive. This vulnerability poses a significant risk to the availability of Wildfly-based services exposed to untrusted networks.

## Impact

The successful exploitation of CVE-2026-15567 results in a denial-of-service condition, rendering the target Wildfly instance unavailable. This vulnerability affects any system running vulnerable versions of Wildfly that expose the CSIv2 interface to unauthenticated users. The primary damage is service disruption, which may impact business operations for sectors relying on Wildfly for enterprise middleware and Java EE application hosting.

## Recommendation

- Monitor for service stability issues and application crashes that coincide with high volumes of traffic directed at the CSIv2 interface of Wildfly instances.
- Patch Wildfly to the latest version provided by the vendor to remediate CVE-2026-15567.
- Implement network-level access controls to restrict exposure of the CSIv2 management and communication interfaces to trusted management subnets only.
- Review application server logs for recurrent OutOfMemoryError exceptions following incoming connection attempts.
