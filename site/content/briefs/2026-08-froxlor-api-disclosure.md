---
title: Froxlor API Credential and 2FA Secret Disclosure
slug: 2026-08-froxlor-api-disclosure
description: Froxlor API endpoints in the Customers, Admins, and Ftps classes leak password hashes and TOTP 2FA secret seeds, enabling offline credential cracking and MFA bypass.
date: "2026-08-18T20:56:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Froxlor
products:
  - Froxlor
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The API returns full database rows including password hashes and TOTP 2FA secret seeds in JSON responses.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7788-ghfq-c6mh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62988
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Froxlor to version 2.3.8 or later
      owner: IT Operations
      due: 24h
      evidence: Remediation provided by GHSA advisory
    - action: Rotate all administrator and customer passwords and 2FA seeds
      owner: IT Operations
      due: 48h
      evidence: Remediation advice regarding exposed TOTP seeds
  hunt_leads:
    - lead: Bulk or repeated calls to api.php targeting Customers/Admins/Ftps listing commands
      technique_id: T1592
      data_needed:
        - webserver access logs (POST body parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates these specific commands reveal sensitive data
  mitigation_plan:
    - priority: immediate
      action: Enforce strict API access controls and auditing
      owner: IT Operations
      addresses: CVE-2026-62988
      evidence: Vulnerability allows authenticated users to exfiltrate data
---

The Froxlor hosting management software (versions prior to 2.3.8) contains a critical information disclosure vulnerability (CVE-2026-62988) in its API command classes. The vulnerability stems from API endpoints in `Customers`, `Admins`, and `Ftps` classes retrieving and returning full database rows directly through the response handler without filtering sensitive data. 

Defenders must recognize that attackers with legitimate, low-privileged API access can invoke these commands to exfiltrate password hashes and TOTP 2FA seeds for administrative, customer, and FTP accounts. This exposure poses a severe risk, as attackers can perform offline cracking on the password hashes and use the leaked TOTP seeds to generate valid second-factor authentication codes, effectively bypassing MFA. The persistence of the TOTP secret makes this a long-term risk for any account that has had its data exposed via the API.

## Impact

The vulnerability allows authenticated API users to retrieve credential-equivalent material for all accounts visible to their API scope. Successful exploitation facilitates unauthorized access to hosting panels, FTP services, and hosted content. Because the disclosure includes both password hashes and 2FA seeds, it enables a full bypass of authentication mechanisms for affected administrative and customer accounts. The scope of impact is limited to the hosting environment but includes both customer and high-privilege administrator data.

## Recommendation

* Patch Froxlor to version 2.3.8 or later immediately to address CVE-2026-62988.
* Audit web server access logs for anomalous API activity, specifically focusing on `POST` requests to `api.php` that invoke `Customers.listing`, `Admins.listing`, or `Ftps.listing` commands.
* For all accounts that were potentially exposed through these API endpoints, initiate a mandatory password reset and 2FA seed rotation.
* Implement strict API key management; verify that API keys are only provisioned to trusted, internal service accounts and enforce the principle of least privilege for API permissions.
* Review web server logs for high-frequency or bulk data requests to the Froxlor API from authorized service accounts, which may indicate exfiltration of credential data.
