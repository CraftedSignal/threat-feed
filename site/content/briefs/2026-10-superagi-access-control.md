---
brief_id: brief-2026-10-30-superagi-access-control
event_id: brief-2026-10-30-superagi-access-control
revision: 1
activity_at: "2026-10-30T19:38:40Z"
title: 'TransformerOptimus SuperAGI: Incorrect access control in get_agent_execution (CVE-2026-51905)'
slug: 2026-10-superagi-access-control
description: SuperAGI version 0.0.14 contains an incorrect access control vulnerability allowing remote authenticated attackers to bypass organization isolation and access unauthorized agent execution configurations.
date: "2026-10-30T19:38:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation is sufficient for identifying the vulnerable endpoint and controller.
cpes:
  - cpe:2.3:a:transformeroptimus:superagi:0.0.14:*:*:*:*:*:*:*
vendors:
  - TransformerOptimus
products:
  - SuperAGI (v0.0.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The endpoint lacks an organization ownership check on the selected agent and execution.
    confidence_band: high
cves:
  - id: CVE-2026-51905
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-51905
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review and restrict access to the /agent_executions_configs/details/ API endpoint
      owner: SOC
      due: 24h
      evidence: The endpoint lacks an organization ownership check on the selected agent and execution.
  hunt_leads:
    - lead: Hunt for enumeration patterns against agent_execution_config endpoints
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attacker supplies victim agent_id and agent_execution_id to /agent_executions_configs/details/agent_id/{agent_id}/agent_execution_id/{agent_execution_id}.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or apply patches for SuperAGI v0.0.14
      owner: IT Operations
      addresses: CVE-2026-51905
      evidence: NVD vulnerability disclosure for CVE-2026-51905.
---

TransformerOptimus SuperAGI version 0.0.14 is affected by an incorrect access control vulnerability in the `get_agent_execution_configuration` controller, specifically within `superagi/controllers/agent_execution_config.py`. The vulnerability enables an authenticated attacker to access sensitive agent execution configurations of other organizations by supplying arbitrary `agent_id` and `agent_execution_id` parameters to the `/agent_executions_configs/details/agent_id/{agent_id}/agent_execution_id/{agent_execution_id}` endpoint. The application fails to verify organizational ownership before returning the requested data.

## Impact
Successful exploitation allows a remote authenticated attacker to retrieve sensitive agent execution configurations belonging to other organizations, potentially leading to unauthorized information disclosure of proprietary workflows or agent logic.

## Recommendation
- Inventory all deployments of SuperAGI v0.0.14.
- Implement strict ingress filtering or WAF rules to restrict access to the `/agent_executions_configs/details/` endpoint if immediate patching is not possible.
- Monitor application logs for abnormal patterns of `agent_id` or `agent_execution_id` traversal where a single user context attempts to access disparate IDs.
