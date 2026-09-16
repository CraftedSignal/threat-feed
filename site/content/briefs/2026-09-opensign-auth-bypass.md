---
title: Authentication Bypass in OpenSign getDocument Function
slug: 2026-09-opensign-auth-bypass
description: OpenSign versions through 2.41.3 contain an authentication bypass vulnerability allowing unauthenticated attackers to retrieve sensitive document data and download tokens when OTP verification is disabled.
date: "2026-09-16T23:52:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opensign:opensign:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cloud-security
  - information-disclosure
vendors:
  - OpenSign
products:
  - OpenSign (<= 2.41.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can supply a document identifier from guest signing links to retrieve complete document details.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The function fails to validate caller identity... allowing unauthenticated attackers to retrieve sensitive document metadata... and valid download tokens.
    confidence_band: high
cves:
  - id: CVE-2026-92794
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92794
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Enforce OTP verification for all sensitive document workflows in OpenSign
      owner: IT Operations
      due: 24h
      evidence: Source states the vulnerability occurs when OTP verification is disabled
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSign to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-92794
      evidence: NVD vulnerability entry
---

OpenSign versions through 2.41.3 are susceptible to an authentication bypass vulnerability in the 'getDocument' cloud function. This flaw occurs specifically when one-time-password (OTP) verification is disabled for a document. By exploiting this, an unauthenticated attacker can supply a known document identifier, typically obtained from guest signing links, to the 'getDocument' endpoint. The application fails to validate the caller's identity or authorization status, returning the full document metadata, details for all signers, sender information, and valid download tokens. This exposure poses a significant risk to data confidentiality and integrity, as it allows unauthorized access to documents and potential exfiltration of sensitive information without requiring legitimate user credentials. Organizations utilizing OpenSign must ensure that authentication mechanisms, such as OTP, are enforced and that the product is updated to a patched version once available.

## Attack Chain

1. Attacker identifies a target document ID, typically by intercepting or observing guest signing links sent to authorized recipients.
2. Attacker verifies that the target document environment is configured with OTP verification disabled, a prerequisite for the bypass.
3. Attacker crafts an HTTP GET or POST request targeting the 'getDocument' cloud function endpoint.
4. Attacker includes the target document identifier in the request parameters.
5. The OpenSign cloud function processes the request without enforcing session-based authentication or verifying the caller's identity.
6. The application responds with a JSON payload containing the complete document record, including signer emails, document metadata, and valid file download tokens.
7. Attacker parses the response to extract the download tokens.
8. Attacker uses the extracted download tokens to exfiltrate the full document content from the storage backend.

## Impact

Successful exploitation allows unauthenticated actors to harvest sensitive PII and confidential documents managed within OpenSign. This can lead to unauthorized information disclosure, compromise of business contracts, and potential supply chain risk depending on the sensitivity of the signed documents.

## Recommendation

1. Review current OpenSign document workflows and verify that OTP verification is mandated for all sensitive signing operations.
2. Monitor web server logs for anomalous patterns of requests to the 'getDocument' endpoint, particularly those originating from unauthorized or unexpected IP ranges or those lacking standard authentication headers.
3. Monitor for high volumes of individual document requests that deviate from typical user behavior patterns.
4. Upgrade OpenSign instances to a version beyond 2.41.3 as soon as vendor patches are available.
