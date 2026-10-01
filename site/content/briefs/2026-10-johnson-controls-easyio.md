---
title: Cleartext Credential Exposure in Johnson Controls EasyIO Neo Controllers
slug: 2026-10-johnson-controls-easyio
description: Johnson Controls EasyIO Neo Series controllers are vulnerable to cleartext transmission of sensitive information via the web management interface, potentially allowing credential and session token interception.
date: "2026-10-01T17:06:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - ot
  - cleartext-transmission
  - cve-2026-64893
vendors:
  - Johnson Controls
products:
  - EasyIO Neo Series EC Controllers (V3.3b62, V3.3b63)
  - EasyIO Neo Series CW Controllers (V3.3b24, V3.3b25)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Johnson Controls is aware of a vulnerability in EasyIO Neo which may allow an attacker to intercept and read sensitive information, including credentials and session data, transmitted in cleartext over the network.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Successful exploitation of this vulnerability could allow an attacker to intercept and read sensitive information, including credentials and session data.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-05
  - https://www.cve.org/CVERecord?id=CVE-2026-64893
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade all affected EasyIO Neo Series EC and CW controllers to the patched firmware versions (EC V3.3b64 or CW V3.3b26)
      owner: IT Operations
      due: 72h
      evidence: Johnson Controls released fixed versions for EasyIO Neo Series EC and CW Controllers.
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP and enforce HTTPS/TLS on all management interfaces
      owner: OT Security
      addresses: CVE-2026-64893
      evidence: Enable and enforce HTTPS/TLS for all web-based management access to the device.
---

Johnson Controls has identified a security vulnerability in the EasyIO Neo Series EC and CW controllers (CVE-2026-64893) involving the cleartext transmission of sensitive data. The vulnerability exists within the web-based management interface of the controllers, where credentials and session information are transmitted over the network without adequate encryption. This exposure facilitates potential man-in-the-middle attacks, allowing unauthorized actors to intercept administrative credentials or active session tokens. Given that these devices manage HVAC, lighting, and energy systems, the potential operational impact of unauthorized access is significant. The vulnerability affects EC firmware versions V3.3b62 and V3.3b63, and CW firmware versions V3.3b24 and V3.3b25. Johnson Controls has addressed this by releasing updated firmware (EC V3.3b64 and CW V3.3b26) which disables insecure HTTP communication by default.

## Impact

Successful exploitation of CVE-2026-64893 allows an attacker to intercept administrative credentials and session tokens. If leveraged, an attacker could gain unauthorized control over building automation systems, potentially disrupting HVAC, lighting, and energy management. These controllers are deployed globally across sectors including critical manufacturing, energy, commercial facilities, and government services. The impact involves potential loss of operational integrity for building management systems and unauthorized access to sensitive facility control interfaces.

## Recommendation

- Update affected devices to the fixed firmware versions immediately: Upgrade EC controllers to V3.3b64 and CW controllers to V3.3b26.
- Disable all HTTP access to controller management interfaces and enforce HTTPS/TLS for all web-based management connections.
- Implement network segmentation to place all building automation controllers on isolated, protected network segments behind firewalls to limit exposure.
- Restrict access to management interfaces to trusted IP addresses using access control lists (ACLs).
- Require the use of VPNs for any remote access to building automation management interfaces to ensure encryption in transit.
