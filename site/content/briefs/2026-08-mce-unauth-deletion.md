---
title: Authorization Flaw in Red Hat Multicluster Engine Clusterclaims-controller
slug: 2026-08-mce-unauth-deletion
description: A vulnerability in the Red Hat multicluster engine (MCE) allows authenticated tenants to delete unauthorized ManagedCluster resources due to a missing ownership check in the clusterclaims-controller.
date: "2026-08-21T03:21:53Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Red Hat
products:
  - multicluster engine
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This vulnerability can lead to a denial of service by enabling unauthorized deletion of ManagedClusters.
    confidence_band: high
cves:
  - id: CVE-2026-73267
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73267
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Red Hat multicluster engine to address CVE-2026-73267
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-73267 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Review RBAC for ClusterClaim resource access
      owner: Security Engineering
      addresses: CVE-2026-73267
      evidence: NVD vulnerability details
---

The clusterclaims-controller component within the Red Hat multicluster engine (MCE) contains an authorization bypass vulnerability identified as CVE-2026-73267. The flaw exists because the controller fails to perform adequate ownership verification when processing ClusterClaim resources. A tenant with standard permissions to create and delete ClusterClaim objects can maliciously manipulate the spec.namespace field within these resources. By specifying arbitrary namespaces, an attacker can coerce the controller into deleting ManagedCluster resources that they do not own, including those managed by the hub or belonging to other tenants. This vulnerability effectively allows for unauthorized resource destruction, leading to a significant denial-of-service condition within the affected multicluster environment. Defenders should prioritize patching this controller to enforce strict ownership validation for ClusterClaim operations.

## Impact

The vulnerability poses a high risk to multicluster environments, enabling a malicious or compromised tenant to perform unauthorized deletions of ManagedCluster resources. Successful exploitation results in a persistent denial-of-service, disrupting cluster management workflows and potential cross-tenant isolation failure. Impact is focused on users of Red Hat multicluster engine deployments.

## Recommendation

- Identify all instances of Red Hat multicluster engine (MCE) within the infrastructure and verify patch availability from the vendor for CVE-2026-73267.
- Review RBAC policies for users with 'create' or 'delete' permissions on ClusterClaim resources to limit the scope of potential abuse during the remediation phase.
- Monitor Kubernetes API audit logs for unusual deletion events targeted at ManagedCluster resources initiated by non-administrative service accounts or tenant-associated users.
