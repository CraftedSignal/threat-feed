---
brief_id: brief-2026-10-30-spring-cloud-gateway-rce
event_id: brief-2026-10-30-spring-cloud-gateway-rce
revision: 1
activity_at: "2026-10-30T09:40:03Z"
title: VMware Spring Cloud Gateway Remote Code Execution (CVE-2022-22947)
slug: 2026-10-spring-cloud-gateway-rce
description: CVE-2022-22947 is a critical remote code execution vulnerability in Spring Cloud Gateway allowing attackers to execute arbitrary code via malicious SpEL expressions injected into dynamic route configurations.
date: "2026-10-30T09:40:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection rule drafted based on known exploitation vectors.
cpes:
  - cpe:2.3:a:vmware:spring_cloud_gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:a:vmware:spring_cloud_gateway:3.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:commerce_guided_search:11.3.2:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_binding_support_function:1.11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_binding_support_function:22.1.3:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_console:22.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_exposure_function:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_function_cloud_native_environment:1.10.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:1.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:1.15.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:22.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:22.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_slice_selection_function:1.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_slice_selection_function:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_security_edge_protection_proxy:22.1.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_service_communication_proxy:1.15.0:*:*:*:*:*:*:*
vendors:
  - VMware
products:
  - Spring Cloud Gateway (< 3.0.7, 3.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can execute arbitrary code by dynamically adding routes containing malicious SpEL expressions through the Actuator endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows attackers to... execute arbitrary code using SpEL expressions within route filters.
    confidence_band: high
cves:
  - id: CVE-2022-22947
    cvss: 10
    epss: 0.98253
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SKYSLIENTLY-CVE-2022-22947-PB-AI
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SKYSLIENTLY-CVE-2022-22947-PB-AI&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2022-22947 Exploitation Attempt - Malicious Route Creation
    description: Detects exploitation attempts against CVE-2022-22947 by identifying POST requests to the gateway routes endpoint containing SpEL expression characters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Check inventory for Spring Cloud Gateway and identify versions < 3.0.7 or 3.1.0.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable versions stated in source.
  hunt_leads:
    - lead: Identify unauthorized access to /actuator/gateway/routes and /actuator/gateway/refresh endpoints.
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit documentation details these endpoints as the primary vector.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Spring Cloud Gateway 3.1.1+ or 3.0.7+.
      owner: IT Operations
      addresses: CVE-2022-22947
      evidence: Remediation suggestions section of source.
---

CVE-2022-22947 is a remote code execution (RCE) vulnerability in Spring Cloud Gateway. The vulnerability allows unauthenticated attackers to inject malicious Spring Expression Language (SpEL) expressions via the Actuator endpoint when creating dynamic routes. When the application refreshes its configuration, the injected expression is evaluated, resulting in arbitrary code execution on the underlying server.

## Attack Chain
1. Attacker identifies an exposed and unprotected Actuator endpoint on the target Spring Cloud Gateway instance.
2. Attacker sends a POST request to `/actuator/gateway/routes/{route_name}` containing a JSON payload with a malicious SpEL expression in the filter arguments.
3. Attacker sends a POST request to `/actuator/gateway/refresh` to trigger the application to load the new route configuration.
4. Attacker sends an HTTP request matching the path defined in the newly created malicious route.
5. The Gateway evaluates the injected SpEL expression during route processing.
6. Arbitrary commands are executed by the application process with the privileges of the service user.

## Impact
The vulnerability has a CVSS 3.1 score of 10.0 (Critical). Successful exploitation leads to full system compromise, allowing for remote code execution, unauthorized data access, and disruption of service.

## Recommendation
- Upgrade VMware Spring Cloud Gateway to version 3.1.1 or 3.0.7 or later.
- Disable the Actuator endpoint if it is not required for operational monitoring.
- If the Actuator endpoint is required, restrict network access using firewall rules or implement mandatory authentication via Spring Security to prevent unauthorized access.
- Audit existing gateway route configurations for unexpected or malicious entries.
