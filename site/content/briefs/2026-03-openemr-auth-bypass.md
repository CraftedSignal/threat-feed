---
title: OpenEMR Missing Authorization Allows Unauthorized Data Deletion
slug: 2026-03-openemr-auth-bypass
description: OpenEMR versions before 8.0.0.3 contain a missing authorization vulnerability in the AJAX deletion endpoint that allows any authenticated user to delete patient data.
date: "2026-03-26T12:00:00Z"
severities:
  - high
tags:
  - openemr
  - authorization-bypass
  - data-deletion
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34053
  - https://github.com/openemr/openemr/security/advisories/GHSA-3vvq-pfq6-pw98
rules:
  - title: Detect OpenEMR Unauthorized Deletion Attempt
    description: Detects attempts to exploit CVE-2026-34053 by monitoring requests to the handle_deletions.php endpoint in OpenEMR.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1555.003
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious OpenEMR AJAX Request to Handle Deletions
    description: Detects POST requests to the OpenEMR handle_deletions.php AJAX endpoint, indicative of potential unauthorized data deletion attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1555.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a widely used open-source electronic health records and medical practice management application, is vulnerable to a significant authorization bypass. Specifically, versions prior to 8.0.0.3 lack proper authorization checks in the `interface/forms/procedure_order/handle_deletions.php` AJAX endpoint. This flaw enables any authenticated user, regardless of their assigned role or privileges, to delete procedure orders, patient answers, and specimen records associated with any patient…
