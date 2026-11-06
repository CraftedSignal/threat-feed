---
brief_id: brief-2026-11-06-openshift-pac-privesc
event_id: brief-2026-11-06-openshift-pac-privesc
revision: 1
activity_at: "2026-11-06T23:27:59Z"
title: 'Red Hat OpenShift Pipelines-as-Code: Privilege escalation (CVE-2026-50240)'
slug: 2026-11-openshift-pac-privesc
description: A privilege escalation vulnerability in Red Hat OpenShift Pipelines-as-Code (PAC) allows low-privileged users to execute unauthorized PipelineRuns with elevated permissions via the Repository custom resource.
date: "2026-11-06T23:27:59Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:redhat:openshift_pipelines-as-code:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - OpenShift Pipelines-as-Code
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A namespace user with only Repository and Secret create/delete permissions can cause PAC to execute attacker-controlled PipelineRuns as the auto-provisioned pipeline ServiceAccount.
    confidence_band: high
cves:
  - id: CVE-2026-50240
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50240
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenShift Pipelines-as-Code to the latest version provided by Red Hat to resolve CVE-2026-50240.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability CVE-2026-50240 documentation
  hunt_leads:
    - lead: Audit creation of Repository and PipelineRun resources within namespaces where users have restricted permissions.
      technique_id: T1068
      data_needed:
        - Kubernetes Audit Logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: PAC does not verify whether the creator of a Repository custom resource has permission to create PipelineRuns.
  mitigation_plan:
    - priority: immediate
      action: Restrict RBAC for users who possess Repository and Secret create/delete permissions in namespaces containing CI/CD pipelines.
      owner: IT Operations
      addresses: CVE-2026-50240
      evidence: An attacker with minimal Repository and Secret create/delete permissions can abuse PAC.
---

A vulnerability exists in OpenShift Pipelines-as-Code (PAC) where the platform fails to verify if a user creating a Repository custom resource has the required permissions to trigger PipelineRuns. An attacker with minimal Repository and Secret create/delete permissions can force PAC to execute arbitrary PipelineRuns using the auto-provisioned ServiceAccount. This ServiceAccount carries the ClusterRole/edit permission by default, leading to privilege escalation within the CI/CD namespace.

## Impact
Successful exploitation allows for unauthorized read access to Secrets, modification or deletion of namespace resources, and potential supply chain injection by executing malicious pipeline logic under a high-privilege ServiceAccount.

## Recommendation
- Inventory all namespaces where OpenShift Pipelines-as-Code is deployed and in use.
- Apply the vendor-provided patch for OpenShift Pipelines-as-Code to address the missing authorization check.
- Review RBAC policies for users with Repository and Secret creation permissions to ensure they are restricted from creating these resources in sensitive CI/CD namespaces until the patch is applied.
