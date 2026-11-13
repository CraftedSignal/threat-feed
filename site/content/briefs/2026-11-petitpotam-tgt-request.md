---
brief_id: brief-2026-11-13-petitpotam-tgt-request
event_id: brief-2026-11-13-petitpotam-tgt-request
revision: 1
activity_at: "2026-11-13T05:40:46Z"
title: PetitPotam Suspicious Kerberos TGT Request
slug: 2026-11-petitpotam-tgt-request
description: This analytic detects suspicious Kerberos TGT requests following the potential abuse of Active Directory Certificate Services (ADCS) in combination with PetitPotam.
date: "2026-11-13T05:40:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
affected_os:
  - windows
references:
  - https://github.com/topotam/PetitPotam
  - https://isc.sans.edu/forums/diary/Active+Directory+Certificate+Services+ADCS+PKI+domain+admin+vulnerability/27668/
  - https://github.com/splunk/security_content/blob/88d689fe8a055d8284337b9fad5d9152b42043db/detections/endpoint/petitpotam_suspicious_kerberos_tgt_request.yml
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_petitpotam_susp_tgt_request.yml
rules:
  - title: PetitPotam Suspicious Kerberos TGT Request
    description: Detects suspicious Kerberos TGT requests that may follow PetitPotam and ADCS abuse. Requires tuning by filtering the Account_Name to the Domain Controller computer accounts.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1187
    data_sources:
      - windows
      - security
rules_count: 1
---

PetitPotam can be used to force a computer to authenticate against a remote server. In combination with Active Directory Certificate Services (ADCS), this technique may allow an attacker to obtain a computer certificate. This certificate can then be leveraged to request a Kerberos Ticket Granting Ticket (TGT).

## Attack Chain
1. Attacker abuses ADCS in combination with PetitPotam to obtain a computer certificate.
2. Attacker leverages the certificate to request a Kerberos TGT.
3. The request generates a 4768 event with potentially unusual fields.

## Recommendation
- Deploy the Sigma rule below to monitor for anomalous 4768 events.
- Tune the detection by filtering the Account_Name to Domain Controller computer accounts.
- Ensure the advanced audit policy setting "Account Logon > Kerberos Authentication Service" is configured for Success/Failure.
