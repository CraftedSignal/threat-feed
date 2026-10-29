---
brief_id: brief-2026-10-29-monailabel-dicom-corruption
event_id: brief-2026-10-29-monailabel-dicom-corruption
revision: 1
activity_at: "2026-10-29T00:11:39Z"
title: 'MONAILabel: Remote Denial of Service and Inference Corruption (CVE-2026-48705)'
slug: 2026-10-monailabel-dicom-corruption
description: An unauthenticated remote attacker can crash the MONAILabel inference pipeline or cause silent medical AI data corruption by uploading crafted DICOM files containing invalid NaN or infinity values.
date: "2026-10-29T00:11:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:monai:monailabel:*:*:*:*:*:*:*:*
  - cpe:2.3:a:pydicom:pydicom:*:*:*:*:*:*:*:*
tags:
  - medical-imaging
  - dicom
  - dos
  - supply-chain
  - cve-2026-48705
vendors:
  - MONAI
  - pydicom
products:
  - MONAILabel (< 1.6.1)
  - MONAI Core (< 1.6.1)
  - pydicom (0.9.7 - 3.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can crash a running MONAILabel server or silently corrupt its medical AI inference results by uploading a single crafted DICOM file (~132 KB) via the REST API.
    confidence_band: high
cves:
  - id: CVE-2026-48705
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-6hp3-vr39-rqw8
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch MONAILabel and MONAI Core to version 1.6.1.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability fixed in version 1.6.1.
  hunt_leads:
    - lead: Search server logs for HTTP 500 errors associated with /infer/ endpoint requests.
      technique_id: T1190
      data_needed:
        - Web server access and application error logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Server crash traceback identifies HTTP 500 triggered by invalid DICOM processing.
  mitigation_plan:
    - priority: immediate
      action: Implement authentication on the MONAILabel REST API.
      owner: IT Operations
      addresses: Unauthenticated API access
      evidence: Default deployment requires no authentication for the REST API.
  gaps:
    - Lack of built-in input validation for spatial metadata in current MONAI versions.
---

MONAILabel and MONAI Core are vulnerable to input validation flaws originating from pydicom's failure to reject non-numeric values in Decimal String (DS) DICOM fields. An unauthenticated attacker can upload malformed DICOM files (approx. 132 KB) via the REST API, which are then persisted in the datastore. These invalid values (NaN/inf) propagate through spatial transforms in the MONAI inference pipeline, resulting in server crashes (Denial of Service) or the generation of geometrically incorrect AI inference results. The issue affects MONAI versions prior to 1.6.1 and pydicom versions 0.9.7 through 3.0.2.

## Attack Chain
1. Attacker identifies a target MONAILabel server with an exposed REST API (default port 8000).
2. Attacker crafts a DICOM file with NaN or infinity values injected into mandatory spatial DS tags (e.g., PixelSpacing, ImagePositionPatient).
3. Attacker submits the crafted file to the server's `PUT /datastore/` endpoint without requiring authentication.
4. The MONAILabel server stores the malicious DICOM file in its permanent datastore.
5. Attacker triggers a standard inference request via `POST /infer/` targeting the stored malicious image ID.
6. The MONAI `PydicomReader` and downstream transforms (`LoadImaged`/`Spacingd`) process the NaN/inf values without validation.
7. The inference pipeline crashes with a `RuntimeError` or produces corrupted AI output depending on the transform stage.

## Impact
- Denial of Service: Repeated crashes of the inference service consuming server CPU and memory.
- Data Corruption: Silent production of incorrect AI segmentation masks when the pipeline does not immediately crash.
- Persistence: Malicious DICOM files remain in the datastore, causing recurrent failures upon future inference requests.

## Recommendation
- Patch MONAILabel and MONAI Core to version 1.6.1 or later immediately.
- Implement strict input validation for spatial metadata on all API-exposed upload endpoints before storing files.
- Restrict network access to the MONAILabel REST API to authorized internal networks only.
- Implement Authentication and Authorization (RBAC) for all MONAILabel API endpoints to prevent unauthenticated uploads.
- Deploy monitoring for `RuntimeError` and `itkGDCMImageIO` related exceptions in inference server logs.
