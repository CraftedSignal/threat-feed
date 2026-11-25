---
brief_id: brief-2026-11-25-eks-cluster-lifecycle
event_id: brief-2026-11-25-eks-cluster-lifecycle
revision: 1
activity_at: "2026-11-25T16:18:10Z"
title: AWS EKS Cluster Created or Deleted
slug: 2026-11-eks-cluster-lifecycle
description: This brief provides a detection rule for monitoring EKS cluster creation and deletion events via AWS CloudTrail to identify potential unauthorized infrastructure lifecycle changes.
date: "2026-11-25T16:18:10Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  likelihood: roughly even chance
tags:
  - cloud
  - infrastructure
  - monitoring
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_eks_cluster_created_or_deleted.yml
  - https://web.archive.org/web/20231015220234/https://any-api.com/amazonaws_com/eks/docs/API_Description
rules:
  - title: AWS EKS Cluster Created or Deleted
    description: Identifies when an EKS cluster is created or deleted via CloudTrail.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
rules_count: 1
---

## Overview

Monitoring Amazon EKS cluster creation and deletion is relevant for identifying infrastructure lifecycle changes. AWS CloudTrail logs can capture the 'CreateCluster' and 'DeleteCluster' API calls directed at the 'eks.amazonaws.com' event source.

## Attack Chain

- Impact (T1485): The creation or deletion of EKS clusters impacts the availability or integrity of containerized infrastructure.

## Recommendation

Deploy the provided detection rule. Evaluate whether the actor performing the EKS cluster creation or deletion is authorized. Investigating unauthorized or unexpected activity is recommended to manage potential misconfigurations or malicious infrastructure changes.
