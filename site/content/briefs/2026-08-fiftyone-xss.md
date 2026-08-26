---
title: Stored XSS in FiftyOne via Dataset Field Descriptions
slug: 2026-08-fiftyone-xss
description: FiftyOne versions are vulnerable to stored cross-site scripting (XSS) due to improper sanitization of dataset field descriptions, allowing attackers to execute arbitrary scripts in the application origin.
date: "2026-08-26T16:21:55Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Voxel51
products:
  - FiftyOne
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Opening a dataset obtained from another party and hovering the field runs the stored markup in the application's origin.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The sidebar field-information component passes the description string to React's dangerouslySetInnerHTML, and no layer between storage and render escapes or sanitises it.
    confidence_band: high
cves:
  - id: CVE-2026-80426
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80426
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch FiftyOne to the latest version to address CVE-2026-80426
      owner: IT Operations
      due: 72h
      evidence: NVD vulnerability disclosure
---

Voxel51's FiftyOne platform contains a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-80426. The vulnerability exists within the 'FieldLabelAndInfo' component, which renders dataset field descriptions using React's 'dangerouslySetInnerHTML' without prior sanitization or escaping. Because these descriptions are stored as part of the dataset schema, the payload persists across database entries and travels with exported or published datasets.

When a victim opens a malicious dataset, the XSS payload executes within the context of the FiftyOne application origin. This origin is shared with the unauthenticated FiftyOne server media route. An attacker can leverage this execution context to read local files on the server or interact with sensitive dataset and operator endpoints, potentially resulting in unauthorized data access or local file disclosure.

## Attack Chain

1. Attacker crafts a malicious dataset with a crafted XSS payload injected into a field's description string.
2. The malicious dataset is exported or distributed to a victim.
3. The victim imports the malicious dataset into their instance of FiftyOne.
4. The victim navigates to the UI component that displays the malicious dataset's field information.
5. The 'FieldLabelAndInfo' component renders the description via 'dangerouslySetInnerHTML', triggering the malicious script.
6. The script executes within the FiftyOne origin and makes requests to the unauthenticated media route.
7. The script reads arbitrary local files or interacts with internal operator endpoints as the authenticated user.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the FiftyOne browser context. This grants an attacker the ability to bypass existing security controls to access sensitive dataset information, trigger operator endpoints, and potentially read local files accessible to the FiftyOne server, impacting data integrity and confidentiality.

## Recommendation

- Upgrade FiftyOne to a patched version that sanitizes field descriptions before rendering.
- Avoid importing or opening datasets from untrusted or unverified third-party sources until the patch is applied.
- Restrict network access to the FiftyOne server to trusted internal users to mitigate the impact of the unauthenticated media route.
