---
title: Authentication Token Theft via OpenMetadata Redirect Vulnerability
slug: 2026-08-openmetadata-auth-bypass
description: OpenMetadata versions prior to 2.0.0 contain a critical vulnerability in the SAML, OIDC, and OAuth2 handlers that allows attackers to redirect sensitive authentication tokens to external, attacker-controlled domains.
date: "2026-08-26T16:22:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - OpenMetadata
products:
  - OpenMetadata (< 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: A request naming a destination the attacker controls therefore causes the server to deliver a valid token for whoever completes the login to that destination.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: Because the token authenticates API calls as that account, a user who follows such a link and authenticates hands over control of their account.
    confidence_band: high
cves:
  - id: CVE-2026-81029
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81029
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade OpenMetadata to 2.0.0
      owner: IT Operations
      due: 48h
      evidence: Version 2.0.0 removes the caller-supplied callback parameter.
  mitigation_plan:
    - priority: immediate
      action: Egress traffic monitoring
      owner: Security Operations
      addresses: CVE-2026-81029
      evidence: Attacker-supplied redirect targets will cause server-side traffic to external domains.
---

OpenMetadata versions prior to 2.0.0 suffer from an insecure redirect vulnerability (CVE-2026-81029) within the `SamlLoginServlet`, OIDC, and OAuth2 handlers. The application fails to validate the `callback` request parameter before storing it in the user's HTTP session. Upon successful authentication, the server automatically appends a valid JWT - along with the user's email and name - to this attacker-supplied destination URL and performs a redirect. This flaw allows an unauthenticated attacker to craft a malicious link that, when clicked and authorized by an unsuspecting user, exfiltrates the user's session token to an external server. Once the attacker obtains this JWT, they can impersonate the victim, performing unauthorized API calls with the victim's privileges. This vulnerability impacts all 1.x releases and requires immediate remediation by upgrading to version 2.0.0 or later.

## Impact

Successful exploitation results in full account takeover for the affected user. By obtaining a valid JWT, an attacker gains persistent unauthorized access to the victim's OpenMetadata account. This poses a significant risk to data integrity and confidentiality, particularly in environments where OpenMetadata integrates with sensitive organizational data stores. The number of potentially affected organizations is high, given the widespread use of OpenMetadata as an enterprise data catalog.

## Recommendation

- Upgrade OpenMetadata instances to version 2.0.0 or later immediately to remove the vulnerable caller-supplied callback parameter logic.
- Audit web server access logs for anomalous outgoing redirects or suspicious outbound traffic patterns originating from the OpenMetadata server to unknown or unauthorized external domains.
- Implement egress filtering at the network level to restrict the OpenMetadata server from initiating connections to untrusted external domains.
- Review all active sessions and rotate credentials for accounts identified in recent logs that match the suspicious redirect pattern.
