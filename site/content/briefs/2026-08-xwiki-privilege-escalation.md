---
title: Privilege Escalation in XWiki Platform via Live Data REST API
slug: 2026-08-xwiki-privilege-escalation
description: A privilege escalation vulnerability in the XWiki Platform Live Data Live Table component allows users with page edit rights to acquire script rights through manipulated REST API requests.
date: "2026-08-19T22:33:58Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - XWiki
products:
  - xwiki-platform-livedata-livetable
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any user who can edit a page in XWiki can use Live Data's edit REST API in XWiki to change the rights on that page.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-45ph-gxxr-gwgw
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade xwiki-platform-livedata-livetable to patched versions
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-53966 official patch recommendation
  hunt_leads:
    - lead: REST API traffic involving Live Data endpoint followed by privilege changes
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source describes misuse of the Live Data edit REST API
---

XWiki Platform is affected by a security flaw (CVE-2026-53966) residing in the Live Data Live Table component. The vulnerability permits an authenticated user with standard edit permissions on a document to escalate their privileges to script rights via the Live Data edit REST API. By manipulating requests to this API, a user can modify document rights directly, effectively bypassing built-in security checks and existing access control listeners associated with document update events. 

Obtaining script rights is a high-severity outcome as it enables the execution of arbitrary Velocity scripts and the injection of unauthorized HTML or JavaScript content into the victim's session. This capability allows for further exploitation of the application or client-side attacks against other users. The issue impacts multiple versions of the xwiki-platform-livedata-livetable package, including versions ranging from 13.4-rc-1 through 18.1.0-rc-1. The vendor has addressed the vulnerability in versions 16.10.17, 17.4.10, 17.10.4, and 18.1.0.

## Impact

Successful exploitation allows a low-privileged user to gain unauthorized script execution capabilities within the XWiki environment. This escalation circumvents security checks implemented in extensions that rely on `UserUpdatingDocumentEvent` listeners. Potential consequences include unauthorized code execution on the server via Velocity scripts, cross-site scripting (XSS) via injected content, and the ability to modify critical document permissions, which can be leveraged to compromise the integrity and confidentiality of the entire wiki instance.

## Recommendation

Prioritize the upgrade of the XWiki platform to the patched versions specified in the security advisory.

* Upgrade the xwiki-platform-livedata-livetable package to version 16.10.17, 17.4.10, 17.10.4, or 18.1.0 as appropriate for your branch to address CVE-2026-53966.
* Audit logs for suspicious activity involving the Live Data REST API, specifically monitoring for frequent modifications to document rights originating from accounts with limited privileges.
* Review all custom security listeners or extensions currently deployed in the XWiki instance to verify if they rely on standard document update events that might be bypassed by this vulnerability.
