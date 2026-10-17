---
title: 'CVE-2026-107762: IDOR Vulnerability in Kirki WordPress Plugin'
slug: 2026-10-kirki-idor
description: The Kirki plugin for WordPress is vulnerable to an Insecure Direct Object Reference (IDOR) flaw via the 'context' parameter, allowing unauthenticated attackers to exfiltrate sensitive user profile data.
date: "2026-10-17T04:48:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kirki:kirki:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Kirki (<= 6.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: User IDs can be enumerated through standard WordPress REST endpoints, facilitating the exploit.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Exploitation requires a published page that uses a Kirki template containing at least one user-type dynamic content block.
    confidence_band: high
cves:
  - id: CVE-2026-107762
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107762
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kirki plugin to latest version
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable up to 6.3.2
  hunt_leads:
    - lead: Unusually high frequency of REST API requests originating from single IP addresses targeting user profile endpoints
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: User IDs can be enumerated through standard WordPress REST endpoints
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kirki to 6.3.3 or higher
      owner: IT Operations
      addresses: CVE-2026-107762
      evidence: Vulnerability fixed in releases following 6.3.2
---

CVE-2026-107762 affects the Kirki plugin for WordPress in all versions up to and including 6.3.2. The vulnerability exists due to improper validation of the 'context' parameter within the plugin's REST API implementation. An unauthenticated attacker can exploit this Insecure Direct Object Reference (IDOR) to access and exfiltrate sensitive profile information for arbitrary WordPress users. 

Exposed data includes user email addresses, display names, nicenames, registration dates, profile image URLs, and various string-valued meta fields such as first names, last names, nicknames, and descriptions. Successful exploitation requires the presence of a published WordPress page that utilizes a Kirki template containing at least one user-type dynamic content block. Since WordPress user IDs are generally enumerable via standard REST endpoints, the barrier to exploitation is low for sites where these specific templates are active.

## Attack Chain

1. Attacker performs reconnaissance on the target WordPress site to verify the presence of the Kirki plugin and published pages.
2. Attacker uses standard WordPress REST API endpoints (e.g., /wp-json/wp/v2/users) to enumerate valid user IDs on the target system.
3. Attacker identifies a published page or template on the site that utilizes a Kirki user-type dynamic content block.
4. Attacker crafts a malicious REST API request targeting the vulnerable Kirki endpoint.
5. Attacker injects a manipulated 'context' parameter to bypass authorization checks associated with the specific user ID.
6. The server processes the request and returns a JSON response containing the sensitive user profile data.
7. Attacker parses the response to exfiltrate email addresses, meta fields, and other user account details.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive user account information. This data can facilitate further targeted attacks, such as account takeover via credential stuffing, spear-phishing campaigns against administrators, or broader reconnaissance for additional system compromise. The scope of impact is limited to the user information stored within the WordPress database, but the ability to perform this unauthenticated and programmatically increases the risk of large-scale data harvesting.

## Recommendation

Prioritized actions for security teams:
- Update the Kirki plugin to the latest version, ensuring all installations are at least version 6.3.3 or higher.
- Audit logs for repeated REST API requests targeting user profiles if anomalous patterns are observed.
- Review all WordPress pages and templates for the use of dynamic user-type content blocks if patching cannot be performed immediately.
- Disable the REST API for public-facing components if the site's functionality does not require it, to mitigate enumeration and exploitation of IDOR vulnerabilities.
