---
title: FreeRDP Protocol Negotiation Bypass via CVE-2026-91949
slug: 2026-09-freerdp-bypass
description: An unauthenticated protocol negotiation vulnerability in FreeRDP servers allows attackers to bypass RDSTLS transport security policies.
date: "2026-09-15T17:41:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:freerdp:freerdp:*:*:*:*:*:*:*:*
vendors:
  - FreeRDP
products:
  - FreeRDP (< 3.31.0)
cves:
  - id: CVE-2026-91949
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91949
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade FreeRDP server to 3.31.0 or later
      owner: IT Operations
      addresses: CVE-2026-91949
      evidence: FreeRDP server versions before 3.31.0 contain a protocol negotiation bypass vulnerability
---

FreeRDP server versions prior to 3.31.0 contain a protocol negotiation bypass vulnerability, tracked as CVE-2026-91949. This flaw allows unauthenticated remote attackers to force an RDP session into RDSTLS mode, even when the server configuration is explicitly set to disable RDSTLS. By sending specifically crafted, incompatible protocol negotiation requests, an attacker triggers a negotiation failure that leads the server to incorrectly fall back or proceed into an insecure RDSTLS handshake. This vulnerability effectively bypasses pre-authentication security restrictions and transport-level policy enforcement. Given the potential for unauthenticated access to the underlying protocol layer, this issue poses a high risk to organizations relying on FreeRDP to enforce strict transport security for remote access services. Organizations should update to version 3.31.0 or later to mitigate this risk.

## Impact

Successful exploitation allows unauthenticated attackers to establish RDSTLS connections in environments where such transport is explicitly prohibited by security policy. This bypasses access controls designed to limit protocol exposure, potentially exposing the server to further pre-authentication exploitation vectors and unauthorized remote connectivity.

## Recommendation

Update all instances of FreeRDP server to version 3.31.0 or later to ensure the protocol negotiation logic correctly enforces transport policies. Since the vulnerability involves protocol-level manipulation, monitor RDP connection logs for unusual negotiation error patterns or unexpected TLS handshake initiations originating from unauthorized external networks.
