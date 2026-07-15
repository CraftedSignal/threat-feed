---
title: MantisBT SOAP API Authentication Bypass and Privilege Escalation (CVE-2026-47156)
slug: 2026-07-mantisbt-auth-bypass
description: A critical authentication bypass vulnerability, CVE-2026-47156, exists in the SOAP API's mci_check_login() function of MantisBT versions 2.28.3 and earlier, allowing an unauthenticated attacker to impersonate any user, including an administrator, by knowing a valid cookie_string and the target username, without needing the target's password, which can lead to full administrator access, extensive data exfiltration, and destructive operations when default self-registration is enabled.
date: "2026-07-15T16:47:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - privilege-escalation
  - web-vulnerability
  - mantisbt
  - cve
vendors:
  - MantisBT
products:
  - MantisBT (2.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The vulnerability is exploitable with zero prior access on default MantisBT installations because self-registration is enabled by default ($g_allow_signup = ON).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any user knowing any valid cookie_string can authenticate as any other user (knowing their username), including the administrator, without knowing the target's password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c2xg-qjqw-2v98
  - https://github.com/mantisbt/mantisbt/commit/e3571c319b1721b41b0dc4b5b5203cbdcbe0c2ee
  - https://mantisbt.org/bugs/view.php?id=37121
---

A critical authentication bypass vulnerability, identified as CVE-2026-47156, has been discovered in MantisBT versions 2.28.3 and earlier. This flaw specifically impacts the `mci_check_login()` function within the application's SOAP API. An attacker can leverage this vulnerability to gain full administrator privileges without needing the administrator's password. The exploitation relies on the attacker knowing any valid `cookie_string` (which can be their own, obtained via self-registration) and the target administrator's username. This zero-prior-access exploit is particularly potent in default MantisBT installations where self-registration is enabled, allowing attackers to easily obtain a valid `cookie_string`. The vulnerability enables comprehensive data exfiltration of bug reports, attachments, user accounts, and configuration data, alongside destructive actions such as deleting projects or issues. Neither the REST API nor the Web UI are affected by this specific flaw.

## Attack Chain

1. **Initial Access (Self-Registration):** The attacker accesses a MantisBT instance where self-registration (`$g_allow_signup = ON`) is enabled by default.
2. **User Creation:** The attacker self-registers for a new user account on the MantisBT instance.
3. **Cookie Acquisition:** The attacker logs into their newly created account via the web UI and extracts their valid `MANTIS_STRING_COOKIE` from their browser's cookies.
4. **SOAP API Request Crafting:** Using the obtained `cookie_string` and the known username of a target administrator, the attacker crafts a malicious SOAP API request targeting the `mci_check_login()` function.
5. **Authentication Bypass:** The crafted SOAP API request is sent to the MantisBT server. The `mci_check_login()` function, due to the vulnerability, fails to properly validate the `cookie_string` against the supplied username, granting the attacker authentication as the target administrator.
6. **Privilege Escalation:** The attacker is now authenticated as the administrator within the SOAP API context, effectively escalating privileges from a basic self-registered user to a full administrator.
7. **Malicious Operations:** The attacker can then utilize the 71 available SOAP operations to perform various malicious activities.
8. **Impact:** This leads to objectives such as full data exfiltration of bug reports, attachments, user accounts, and configuration details, or destructive actions like deleting projects, issues, attachments, tags, categories, and versions.

## Impact

The successful exploitation of CVE-2026-47156 grants attackers full administrator access to the MantisBT SOAP API from zero prior access, especially in default installations where self-registration is enabled. This level of access permits extensive data exfiltration, including all issues (public and private), notes, attachments, user accounts (IDs, names, emails), and non-private configuration values across all projects. Attackers can also perform destructive operations such as deleting projects, issues, attachments, tags, categories, and versions, or manipulate data by creating/modifying issues and managing project structures. This critical flaw allows for comprehensive compromise of the MantisBT instance and its contained data.

## Recommendation

* **Patch CVE-2026-47156 immediately:** Update MantisBT to a version patched against [CVE-2026-47156](https://github.com/mantisbt/mantisbt/commit/e3571c319b1721b41b0dc4b5b5203cbdcbe0c2ee).
* **Disable self-registration:** If not strictly required for your operational environment, disable `$g_allow_signup` in your MantisBT configuration to prevent unauthenticated users from easily obtaining a `cookie_string` for exploitation.
* **Monitor web server logs for suspicious SOAP API activity:** While no specific exploitation signature is provided, monitor web server logs for unusual or high volumes of requests to SOAP API endpoints, especially those involving `mci_check_login()`, particularly from newly registered users or IP addresses not typically associated with administrative activity.
