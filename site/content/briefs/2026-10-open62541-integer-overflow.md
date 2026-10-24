---
brief_id: brief-2026-10-24-open62541-integer-overflow
event_id: brief-2026-10-24-open62541-integer-overflow
revision: 1
activity_at: "2026-10-24T14:16:30Z"
title: 'open62541: Integer overflow in UA_DataType_fromStructureDescription (CVE-2026-116014)'
slug: 2026-10-open62541-integer-overflow
description: An integer overflow in the open62541 library allows a malicious OPC UA server to trigger heap corruption in clients, potentially leading to remote code execution.
date: "2026-10-24T14:16:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Validated against NVD source material
cpes:
  - cpe:2.3:a:open62541:open62541:*:*:*:*:*:*:*:*
vendors:
  - open62541
products:
  - open62541 (< 1.5.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A malicious OPC UA server can supply DataType definitions via UA_Client_getRemoteDataTypes(), causing decodeBinaryStructure() to overflow the heap, crashing clients or enabling code execution.
    confidence_band: high
cves:
  - id: CVE-2026-116014
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116014
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch open62541 library to version 1.5.7 or higher across all affected applications.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability remediation requires updating to version 1.5.7.
  hunt_leads:
    - lead: Identify applications utilizing the open62541 library that perform external OPC UA client connections.
      technique_id: T1203
      data_needed:
        - Software Bill of Materials (SBOM)
        - Dependency manifests
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability is inherent to the parsing logic in the library used by client applications.
  mitigation_plan:
    - priority: immediate
      action: Upgrade open62541 to version 1.5.7 or later.
      owner: IT Operations
      addresses: CVE-2026-116014
      evidence: CVE-2026-116014 advisory.
---

The open62541 library contains an integer overflow vulnerability in the UA_DataType_fromStructureDescription() function. The vulnerability occurs when processing 16-bit memSize fields within custom structure definitions. A malicious OPC UA server can deliver crafted DataType definitions via the UA_Client_getRemoteDataTypes() function, resulting in an overflow during calls to decodeBinaryStructure(). Successful exploitation causes heap corruption, which may lead to application crashes or remote code execution. This affects open62541 versions 1.5.0 through 1.5.6.

## Impact

Successful exploitation may result in heap corruption, causing service disruption via application crashes or potential remote code execution on the client-side system.

## Recommendation

Update the open62541 library to version 1.5.7 or later to address the integer overflow vulnerability in structure description parsing. Organizations utilizing libraries built on open62541 should identify internal applications using the library and schedule updates for the identified software.
