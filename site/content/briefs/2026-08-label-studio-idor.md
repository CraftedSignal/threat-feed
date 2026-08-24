---
title: IDOR Vulnerability in Label Studio Annotation API
slug: 2026-08-label-studio-idor
description: Label Studio contains an insecure direct object reference (IDOR) vulnerability, CVE-2026-76073, allowing authenticated users to read, modify, or delete annotations across organizational boundaries by enumerating sequential identifiers.
date: "2026-08-24T20:06:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - api-security
  - data-exfiltration
vendors:
  - Heartex
products:
  - Label Studio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The view's permission_required entries name annotations.view, annotations.change and annotations.delete, and label_studio/core/permissions.py registers every permission with rules.is_authenticated, so the check is satisfied by any logged-in account and no object-level organization test runs.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Annotation identifiers are sequential integers, so an authenticated user of one organization can enumerate identifiers to read, modify and delete annotations belonging to other organizations on the same instance.
    confidence_band: high
cves:
  - id: CVE-2026-76073
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76073
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and patch Label Studio instance upon availability of vendor update
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-76073
    - action: Monitor API logs for suspicious enumeration patterns directed at annotation endpoints
      owner: SOC
      due: 24h
      evidence: Annotation identifiers are sequential integers
  hunt_leads:
    - lead: Search logs for high frequency access to /api/annotations/ with sequential integer IDs from non-admin accounts
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Annotation identifiers are sequential integers, so an authenticated user of one organization can enumerate identifiers
  mitigation_plan:
    - priority: immediate
      action: Restrict instance access to trusted users
      owner: IT Operations
      addresses: CVE-2026-76073
      evidence: Unscoped queryset allows any authenticated user access to all data
---

Label Studio, a popular open-source data labeling tool maintained by Heartex, contains a critical insecure direct object reference (IDOR) vulnerability identified as CVE-2026-76073. The flaw exists within the 'AnnotationAPI' and 'AnnotationConvertAPI' endpoints defined in 'label_studio/tasks/api.py'. The application fails to properly scope querysets to the requesting user's organization. While other endpoints, such as the task-specific API, correctly constrain data access by checking 'project__organization', the annotation endpoints default to 'Annotation.objects.all()'. Because these endpoints only verify basic authentication rather than enforcing object-level authorization, any logged-in user can access any annotation in the system. Furthermore, since annotation identifiers are assigned as sequential integers, an attacker can trivially enumerate these IDs to exfiltrate or manipulate sensitive annotation data belonging to other organizations hosted on the same instance. This vulnerability poses a significant risk to the confidentiality and integrity of proprietary datasets within multi-tenant Label Studio environments.

## Impact

The vulnerability allows any authenticated user to gain unauthorized access to annotation data across organizational silos. Impact includes the potential for full data exfiltration of labels, the modification of labeling tasks which could poison machine learning pipelines, and the deletion of project work. This is particularly critical in multi-tenant environments where organizations expect strict data isolation.

## Recommendation

1. Upgrade Label Studio to a patched version once provided by Heartex to remediate CVE-2026-76073.
2. Implement an application-layer firewall or web application firewall (WAF) to monitor for anomalous spikes in API requests targeting the annotation endpoints (e.g., sequentially incrementing IDs).
3. Audit webserver access logs for high-volume HTTP GET, PATCH, and DELETE requests to '/api/annotations/' from low-privileged user accounts.
4. Ensure that all organizational members are vetted and that the instance is restricted to trusted users until the patch is applied.
