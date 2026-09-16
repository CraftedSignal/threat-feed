---
title: Authorization Bypass in yshop-crm CrmCustomerController
slug: 2026-09-yshop-crm-auth-bypass
description: An authorization bypass vulnerability in yshop-crm versions 2.1.3 and earlier allows authenticated users to manipulate Redis-based customer policies, leading to service disruption and data loss.
date: "2026-09-16T13:49:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yshop-crm:yshop-crm:*:*:*:*:*:*:*:*
vendors:
  - yshop-crm
products:
  - yshop-crm (<= 2.1.3)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated back-office user can exploit this flaw to manipulate Redis keys that control lead-allocation and customer auto-recycling policies.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Successful exploitation can lead to mass customer data deletion, disruption of lead recycling processes, or a denial-of-service condition.
    confidence_band: high
cves:
  - id: CVE-2026-92456
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92456
rules:
  - title: Detect CVE-2026-92456 Exploitation - Unauthorized Access to Redis CRM Endpoints
    description: Detects unauthorized or suspicious interaction with CRM endpoints responsible for managing Redis settings, indicative of CVE-2026-92456 exploitation.
    platform: sigma
    severity: high
    tactics:
      - impact
      - persistence
    techniques:
      - T1068
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review webserver access logs for attempts to call CrmCustomerController/saveRedisSet or getRedisSet
      owner: SOC
      due: 24h
      evidence: NVD vulnerability description identifies specific vulnerable endpoints
  mitigation_plan:
    - priority: immediate
      action: Restrict access to back-office CRM administrative endpoints until a vendor-supplied patch is applied
      owner: IT Operations
      addresses: CVE-2026-92456
      evidence: Source document identifies authorization bypass as the root cause
---

yshop-crm versions up to and including 2.1.3 contain a critical authorization flaw within the CrmCustomerController. The application fails to enforce proper access control checks on the saveRedisSet and getRedisSet endpoints. This vulnerability allows any user with authenticated back-office access to perform unauthorized read and write operations on critical Redis keys. These keys govern installation-wide business logic, specifically lead-allocation and customer auto-recycling policies. By manipulating these settings, an attacker can disrupt the core functionality of the CRM, leading to the deletion of customer records, the disabling of lead recycling mechanisms, or a denial-of-service state that prevents the creation of new customers across the entire deployment. Defenders should prioritize auditing logs for unauthorized access to these specific administrative endpoints.

## Impact

Successful exploitation of this vulnerability allows unauthorized modification of business-critical CRM settings. The primary impact includes the potential for mass deletion of customer data, prolonged business process disruption through the disabling of lead recycling, and an application-wide denial-of-service condition where customer creation becomes impossible. The scope of impact is limited to the CRM's internal data and business operations but poses a significant risk to organizational data integrity and service availability.

## Recommendation

Prioritized, concrete actions for security operations and IT teams:
- Immediately audit application logs for frequent or unauthorized HTTP POST/GET requests directed at the saveRedisSet and getRedisSet endpoints within the CrmCustomerController.
- Implement strict role-based access control (RBAC) validation for administrative CRM functions to prevent non-privileged users from interacting with backend controller logic.
- Monitor Redis-related application calls for unexpected key modifications that deviate from standard administrative workflows.
- If a patch becomes available for yshop-crm, prioritize testing and deployment to all production instances immediately.
