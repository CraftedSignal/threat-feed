---
title: Authentication Bypass and RCE in CentreStack via Hardcoded Cryptographic Key
slug: 2026-07-centrestack-hardcoded-key
description: CentreStack versions prior to 17.5 contain a hardcoded cryptographic key vulnerability, allowing unauthenticated attackers to forge authentication tokens and execute arbitrary code.
date: "2026-07-30T13:40:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - remote-code-execution
  - hardcoded-key
vendors:
  - CentreStack
products:
  - CentreStack (< 17.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: CentreStack before 17.5 contains a hardcoded cryptographic key vulnerability that allows unauthenticated attackers to forge arbitrary encrypted tokens.
    confidence_band: high
cves:
  - id: CVE-2026-54363
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54363
---

CentreStack versions prior to 17.5 contain a critical cryptographic vulnerability where a hardcoded 'SysNumber' value is utilized as entropy for the AccessTicket.Encrypt() and AccessTicket.Decrypt() functions. Because this key is consistent across all installations, an unauthenticated attacker can effectively forge encrypted tokens. By crafting valid 'x-glad-auth' headers, an attacker can bypass authentication to access sensitive, privileged API endpoints. A primary objective identified for this exploit chain is the 'acquiretenantbackuptoken' endpoint, which facilitates the retrieval of a Domain Administrator IdentityTicket. Successful exploitation grants the attacker administrative control over the CentreStack instance, enabling remote code execution on the underlying server. This vulnerability represents a significant risk to organizations managing file server access and remote data synchronization via CentreStack, as it provides a direct path from unauthenticated network access to full system compromise.

## Attack Chain

1. An unauthenticated attacker identifies an internet-facing CentreStack instance.
2. The attacker uses the known hardcoded 'SysNumber' to replicate the encryption routine used for AccessTicket generation.
3. The attacker crafts a malicious 'x-glad-auth' HTTP header using the forged token.
4. The attacker sends a crafted request to the 'acquiretenantbackuptoken' privileged API endpoint.
5. The backend service validates the forged token as authentic due to the static entropy key.
6. The server returns a high-privileged Domain Administrator IdentityTicket to the attacker.
7. The attacker uses the stolen IdentityTicket to authenticate to administrative API endpoints.
8. The attacker interacts with file management or configuration APIs to execute arbitrary commands on the host server.

## Impact

Successful exploitation of this vulnerability leads to full unauthenticated remote code execution on the affected CentreStack server. This allows for complete data exfiltration, modification of system configurations, and lateral movement within the corporate network. Because this is a systemic vulnerability in the product's cryptographic implementation, all installations prior to version 17.5 are at risk of total compromise without requiring prior knowledge of legitimate user credentials.

## Recommendation

Prioritized actions for detection engineering teams:
- Upgrade CentreStack instances to version 17.5 or later immediately as the primary remediation for CVE-2026-54363.
- Monitor web server logs for anomalous 'POST' or 'GET' requests to the '/acquiretenantbackuptoken' API endpoint originating from non-authenticated or external IP addresses.
- Implement strict network perimeter controls to restrict access to CentreStack management API endpoints to trusted internal IP ranges only.
- Deploy WAF rules to inspect and filter suspicious 'x-glad-auth' headers that deviate from expected token formatting or originate from suspicious sources.
