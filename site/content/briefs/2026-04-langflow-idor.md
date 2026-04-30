---
title: IBM Langflow Desktop Unauthenticated Image Access via IDOR
slug: 2026-04-langflow-idor
description: IBM Langflow Desktop versions 1.0.0 through 1.8.4 are vulnerable to an indirect object reference (IDOR) vulnerability (CVE-2026-4503), allowing unauthenticated users to view other users' images due to a user-controlled key.
date: "2026-04-30T21:16:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - idor
  - vulnerability
  - privilege-escalation
vendors:
  - IBM
products:
  - Langflow Desktop
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4503
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4503
  - https://www.ibm.com/support/pages/node/7271099
rules:
  - title: Langflow Desktop Image Access via User-Controlled Key
    description: Detects attempts to access images in Langflow Desktop using a potentially malicious or manipulated user-controlled key, indicative of an indirect object reference (IDOR) vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Langflow Desktop Unauthorized Image Access
    description: Detects unauthorized attempts to access image resources on the Langflow Desktop server by monitoring HTTP response codes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Langflow Desktop versions 1.0.0 through 1.8.4 are susceptible to an indirect object reference (IDOR) vulnerability, designated as CVE-2026-4503. This flaw enables unauthenticated attackers to access and view images belonging to other users. The vulnerability arises from the application's reliance on a user-controlled key to reference objects, which can be manipulated to bypass authorization checks and gain unauthorized access to sensitive image data. This poses a risk to user privacy and data security, as attackers can potentially view confidential or personal images without proper authentication.

## Attack Chain

1. An unauthenticated attacker identifies a user-controlled key used to reference image objects within Langflow Desktop.
2. The attacker modifies this key to point to another user's image object.
3. The attacker sends a request to the Langflow Desktop application using the modified key.
4. The application, due to the IDOR vulnerability, fails to properly validate the attacker's authorization to access the requested image object.
5. The application retrieves and returns the image data associated with the targeted user's image.
6. The attacker views the image without authentication.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to view other users' images within IBM Langflow Desktop. This can lead to a breach of privacy, as sensitive or personal images may be exposed. The number of affected users depends on the number of installations of Langflow Desktop within the vulnerable version range (1.0.0 through 1.8.4).

## Recommendation

*   Apply the security patch or upgrade to a version of IBM Langflow Desktop that addresses CVE-2026-4503 as detailed in the IBM advisory.
*   Implement stricter authorization checks on image object references to prevent unauthorized access, mitigating CVE-2026-4503.
