---
brief_id: brief-2026-11-06-skylinedataminer-brokergateway-vuln
event_id: brief-2026-11-06-skylinedataminer-brokergateway-vuln
revision: 1
activity_at: "2026-11-06T19:23:35Z"
title: Skyline DataMiner BrokerGateway embedded API key exposure (CVE-2026-89017)
slug: 2026-11-skylinedataminer-brokergateway-vuln
description: An unauthenticated API key vulnerability in Skyline DataMiner BrokerGateway allows attackers to retrieve internal keys and NATS credentials to gain unauthorized message-bus access via TCP port 4222.
date: "2026-11-06T19:23:35Z"
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
cpes:
  - cpe:2.3:a:skyline:dataminer_brokergateway:*:*:*:*:*:*:*:*
tags:
  - cve-2026-89017
  - network
  - nats
  - credential-exposure
vendors:
  - Skyline
products:
  - DataMiner BrokerGateway (< 10.6.9 CU1, < 10.6.0 CU7, < 10.5.0 CU19, < 10.4.0 CU22)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Skyline DataMiner BrokerGateway contains an embedded API key vulnerability that allows unauthenticated attackers to retrieve the installation-specific BrokerGateway key.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Attackers can use the retrieved key to obtain the unrestricted DataMinerUser.creds NATS credential and gain trusted message-bus access via TCP port 4222.
    confidence_band: high
cves:
  - id: CVE-2026-89017
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89017
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch DataMiner instances to the specified fixed versions
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is fixed in DataMiner 10.6.9 CU1, 10.6.0 CU7, 10.5.0 CU19, and 10.4.0 CU22
  hunt_leads:
    - lead: Identify unauthorized TCP 4222 connections to DataMiner BrokerGateway from external or untrusted internal subnets
      technique_id: T1021
      data_needed:
        - Firewall or flow logs capturing inbound connections to port 4222
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers gain trusted message-bus access via TCP port 4222
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to port 4222 to known, authorized management IPs only
      owner: IT Operations
      addresses: CVE-2026-89017
      evidence: Attackers gain trusted message-bus access via TCP port 4222
---

Skyline DataMiner BrokerGateway versions prior to 10.6.9 CU1, 10.6.0 CU7, 10.5.0 CU19, and 10.4.0 CU22 contain a vulnerability where an embedded API key is retrievable by unauthenticated attackers even when the pairing mode is disabled. Successful exploitation enables an attacker to retrieve the DataMinerUser.creds NATS credentials and gain unauthorized, trusted access to the message-bus via TCP port 4222.

## Impact
Unauthorized actors can obtain trusted message-bus access to the DataMiner system without prior credentials, potentially allowing for the interception or injection of system messages.

## Recommendation
Patch DataMiner systems to the fixed versions immediately: 10.6.9 CU1, 10.6.0 CU7, 10.5.0 CU19, or 10.4.0 CU22. Inventory all internet-facing instances of DataMiner BrokerGateway and restrict network access to the NATS message-bus port 4222 to trusted internal segments only.
