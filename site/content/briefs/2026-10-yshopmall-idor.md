---
title: CVE-2026-110119 - Insecure Direct Object Reference in Yshopmall
slug: 2026-10-yshopmall-idor
description: Yshopmall through version 2.0.0 contains an Insecure Direct Object Reference (IDOR) vulnerability that allows authenticated members to access, modify, or delete the shipping addresses of other users.
date: "2026-10-13T18:37:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yshopmall:yshopmall:*:*:*:*:*:*:*:*
vendors:
  - Yshopmall
products:
  - Yshopmall (<= 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: Attackers can enumerate sequential address ids via /address/detail/{id}, /address/del and /address/edit to expose recipient names, phone numbers and addresses.
    confidence_band: high
cves:
  - id: CVE-2026-110119
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110119
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web access logs for sequential ID enumeration attempts targeting /address/ endpoints
      owner: SOC
      due: 24h
      evidence: Source notes enumeration of sequential address IDs via specific URI paths.
  mitigation_plan:
    - priority: immediate
      action: Implement strict object-level access control on the identified address API endpoints
      owner: IT Operations
      addresses: CVE-2026-110119
      evidence: Vulnerability is an IDOR flaw requiring authorization logic.
---

Yshopmall versions through 2.0.0 contain an Insecure Direct Object Reference (IDOR) vulnerability within the member address API. This flaw arises from insufficient access control checks when processing requests directed at specific address identifiers. An authenticated attacker can exploit this by manipulating the sequential ID parameters used in API endpoints to perform unauthorized actions on behalf of other users. By targeting these endpoints, an attacker can exfiltrate sensitive personal identifiable information (PII), including recipient names, phone numbers, and physical shipping addresses, or perform destructive actions such as deleting or overwriting address entries. Because the identifiers are sequential, an attacker can automate discovery of other users' data, posing a significant risk to user privacy and account integrity.

## Attack Chain

1. The attacker creates or accesses an existing legitimate account on the target Yshopmall instance.
2. The attacker authenticates to the application and inspects outgoing HTTP traffic to identify the address management API endpoints.
3. The attacker observes that the API uses sequential integer IDs in parameters for endpoints like /address/detail/{id}.
4. The attacker crafts a series of HTTP GET requests to /address/detail/{id} while incrementing the {id} parameter to enumerate address objects belonging to other users.
5. The application fails to validate whether the authenticated session user owns the requested address ID.
6. The application returns the requested recipient names, phone numbers, and physical addresses of other members in the HTTP response.
7. The attacker repeats this process using POST or DELETE methods on /address/edit and /address/del to modify or remove victim address information.

## Impact

The successful exploitation of this vulnerability results in the unauthorized exposure of PII for the entire customer base of an affected instance. Beyond privacy breaches, the ability to delete or modify shipping addresses can disrupt order fulfillment and lead to financial losses. Given the sequential nature of the address IDs, this vulnerability is highly susceptible to automated scraping, potentially leading to a mass exfiltration event of user data.

## Recommendation

Prioritized actions for security teams:
- Identify and restrict access to the Yshopmall address API endpoints if the application cannot be immediately updated.
- Implement robust object-level authorization checks in the application code to ensure the authenticated user ID matches the ownership of the requested resource ID.
- Patch Yshopmall to a version containing the fix for CVE-2026-110119 as soon as it becomes available from the vendor.
- Monitor web server logs for anomalous high-frequency access patterns to /address/detail/, /address/del, or /address/edit, especially from authenticated accounts requesting sequential numeric IDs.
