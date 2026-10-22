---
brief_id: brief-2026-10-22-net-libssh-mitm
event_id: brief-2026-10-22-net-libssh-mitm
revision: 1
activity_at: "2026-10-22T01:36:30Z"
title: 'Net::LibSSH: Improper host key verification (CVE-2026-94423)'
slug: 2026-10-net-libssh-mitm
description: The Net::LibSSH Perl module fails to verify host keys against known_hosts during connection establishment, enabling man-in-the-middle attacks.
date: "2026-10-22T01:36:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:net::libssh_project:net::libssh:*:*:*:*:*:perl:*:*
tags:
  - supply-chain
  - vulnerability
  - perl
  - ssh
products:
  - Net::LibSSH (< 0.004)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: This vulnerability allows for man-in-the-middle attacks where an attacker can intercept or spoof SSH traffic, as the client does not validate the identity of the server.
    confidence_band: high
cves:
  - id: CVE-2026-94423
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/300
  - https://metacpan.org/dist/Net-LibSSH
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Net::LibSSH to 0.004 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-94423 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade Net::LibSSH to 0.004 or later
      owner: IT Operations
      addresses: CVE-2026-94423
      evidence: Advisory states versions before 0.004 are affected
---

The Perl distribution Net::LibSSH contains a vulnerability (CVE-2026-94423) where the connect function fails to perform host key verification. This allows an attacker positioned in a man-in-the-middle capacity to intercept or spoof SSH traffic, as the client implicitly trusts any server it connects to. This affects all versions of Net::LibSSH prior to 0.004.

## Impact
Successful exploitation allows for man-in-the-middle attacks, potentially leading to the interception of sensitive data, credentials, or the execution of malicious commands on the client system if the SSH session is subsequently used for administrative operations.

## Recommendation
- Update the Net::LibSSH Perl module to version 0.004 or later.
- Audit applications utilizing Net::LibSSH to identify instances where SSH connections are established to untrusted or external endpoints.
- Implement network-level controls to restrict SSH outbound access to known, verified server IP ranges.
