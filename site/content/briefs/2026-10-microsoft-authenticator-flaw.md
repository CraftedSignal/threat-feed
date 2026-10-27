---
brief_id: brief-2026-10-27-microsoft-authenticator-flaw
event_id: brief-2026-10-27-microsoft-authenticator-flaw
revision: 1
activity_at: "2026-10-27T15:38:30Z"
title: 'Microsoft Authenticator: Token theft via AccountChooserActivity (CVE-2026-80097)'
slug: 2026-10-microsoft-authenticator-flaw
description: A vulnerability in Microsoft Authenticator for Android (CVE-2026-80097) allows malicious applications to impersonate trusted services and intercept sign-in tokens for victim work accounts.
date: "2026-10-27T15:38:30Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: unlikely
qa_status:
  verdict: pass
  validation_status: Patch status needs verification via mobile device fleet management telemetry.
cpes:
  - cpe:2.3:a:microsoft:authenticator:*:*:*:*:*:android:*:*
vendors:
  - Microsoft
products:
  - Authenticator (< 6.2606.4246)
affected_os:
  - Android
cves:
  - id: CVE-2026-80097
    cvss: 8.6
    epss: 0.00442
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/microsoft-authenticator-flaw-let.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Force update of Microsoft Authenticator to 6.2606.4246 via MDM
      owner: IT Operations
      due: 48h
      evidence: Microsoft fixed it in Authenticator for Android version 6.2606.4246
  hunt_leads:
    - lead: Identify devices running vulnerable versions of Microsoft Authenticator (< 6.2606.4246) in MDM console
      technique_id: T1506.001
      data_needed:
        - MDM mobile device inventory report
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Microsoft fixed it in Authenticator for Android version 6.2606.4246, so anyone using the app should update.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Microsoft Authenticator for Android to version 6.2606.4246
      owner: IT Operations
      addresses: CVE-2026-80097
      evidence: Microsoft tracks the flaw as CVE-2026-80097 and fixed it in Authenticator for Android version 6.2606.4246
---

Microsoft has addressed a vulnerability (CVE-2026-80097) in the Microsoft Authenticator app for Android that enabled unauthorized applications to impersonate trusted services (e.g., Teams, Outlook). The flaw resided in the 'AccountChooserActivity' component, which could be invoked by any installed application to initiate a token request. By supplying spoofed metadata, an attacker could deceive the Authenticator broker into returning valid authentication tokens for a user's work account. Microsoft confirms that successful exploitation requires the victim to complete a sign-in flow within the application. The vulnerability is rated "Important" with a CVSS score of 8.6. There is no evidence of exploitation in the wild.

## Impact

Successful exploitation allows an attacker to authenticate as the victim, granting full access to resources accessible via the Microsoft Graph API, including email, files, and calendar items associated with the work account signed into the Authenticator app on the device.

## Recommendation

- Update Microsoft Authenticator for Android to version 6.2606.4246 or later immediately.
- For organizations using Mobile Device Management (MDM), enforce a minimum version policy for Microsoft Authenticator across all managed Android endpoints.
- Review and audit application permissions on mobile devices to identify and remove suspicious or unauthorized apps that may be leveraging this or similar brokering components.
