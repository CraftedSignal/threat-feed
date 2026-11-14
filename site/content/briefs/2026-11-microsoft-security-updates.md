---
brief_id: brief-2026-11-microsoft-security-updates
event_id: brief-2026-11-microsoft-security-updates
revision: 3
activity_at: "2026-11-14T13:56:38Z"
revision_history:
  - revision: 2
    at: "2026-11-11T09:46:57Z"
    checksum: sha256:0b19bee6b185c9dbfaa52b420a0e458c1dd96c4fb3a5f0b56d25ba90f2534870
    summary: added CVE-2026-118707
    changed_fields:
      - claim_state
      - content
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84010
  - revision: 3
    at: "2026-11-14T13:56:38Z"
    checksum: sha256:ed79062aa784cd9965e21264662b4ea9016cc47f0275c1ed68c8fd7bffceda9a
    summary: 'merged coverage from Microsoft Windows Graphics Kernel: Heap-based buffer overflow (CVE-2026-95922)'
    changed_fields:
      - content
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - source_assessment
      - summary
      - title
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-95922
title: 'Microsoft Windows Graphics Kernel: Heap-based buffer overflow (CVE-2026-95922)'
slug: 2026-11-microsoft-security-updates
description: A heap-based buffer overflow vulnerability in the Windows Graphics Kernel allows a locally authenticated attacker to elevate privileges.
date: "2026-11-02T21:54:23Z"
lastmod: "2026-11-14T13:55:58Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:office_2021:-:*:*:*:ltsc:-:*:*
  - cpe:2.3:a:microsoft:office_2024:-:*:*:*:ltsc:-:*:*
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-109469
    kev_status: "false"
  - id: CVE-2026-109454
    product: Office SharePoint
    cvss: 9
    kev_status: "false"
  - id: CVE-2026-120002
    product: SharePoint
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-80095
    cvss: 9
    kev_status: "false"
  - id: CVE-2026-105505
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-105586
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-88176
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-114167
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-114164
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109485
    cvss: 6.3
    kev_status: "false"
  - id: CVE-2026-105578
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109455
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-109491
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-70120
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-109492
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-114165
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-109487
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-96054
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-108447
    cvss: 8.8
    epss: 0.00618
    kev_status: "false"
  - id: CVE-2026-88236
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109472
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109460
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-105512
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-95896
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-96158
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-95901
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-96078
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-85838
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109456
    cvss: 4.6
    kev_status: "false"
  - id: CVE-2026-109466
    cvss: 8
    kev_status: "false"
  - id: CVE-2026-113759
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-95891
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-112982
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-96157
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-112807
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-85839
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-69901
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-95882
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-112974
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-109464
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112985
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-119991
    cvss: 5.9
    kev_status: "false"
  - id: CVE-2026-122196
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-109494
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110050
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110057
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-108470
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-112754
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-109499
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112724
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111295
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112716
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-88222
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110045
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-111309
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-122194
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109504
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-105492
    cvss: 5.3
    kev_status: "false"
  - id: CVE-2026-118208
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-110059
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111304
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110056
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-111288
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-112718
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-96150
    cvss: 5.6
    kev_status: "false"
  - id: CVE-2026-123391
    product: Office SharePoint
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109493
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-119987
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-111292
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-110049
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-112734
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111306
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-120789
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123383
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123384
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-108469
    cvss: 6.8
    kev_status: "false"
  - id: CVE-2026-110043
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110064
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112714
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118149
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123376
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111285
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112715
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123375
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110061
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109495
    cvss: 6.6
    kev_status: "false"
  - id: CVE-2026-110053
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-110060
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-114162
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-118150
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109501
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-120785
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110067
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111305
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112729
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118207
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123378
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-112720
    cvss: 5.5
    kev_status: "false"
  - id: CVE-2026-124179
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-111296
    cvss: 8
    kev_status: "false"
  - id: CVE-2026-112719
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-120791
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111298
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110047
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111287
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-124187
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-122987
    cvss: 5.9
    kev_status: "false"
  - id: CVE-2026-111310
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110054
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112735
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111307
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-124227
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-111302
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-112722
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111299
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-109502
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112739
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-122172
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-124233
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-119937
    cvss: 6.6
    kev_status: "false"
  - id: CVE-2026-110046
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-119816
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-110066
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-112738
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-109498
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-110068
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112721
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-124174
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-124185
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-96067
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-110058
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-116928
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-119943
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-116718
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-124228
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110052
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-112731
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-120786
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-121674
    cvss: 6.1
    kev_status: "false"
  - id: CVE-2026-116925
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-116927
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118709
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-122979
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-119986
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118152
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-119880
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-118298
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-120790
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118718
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-123380
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118723
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-120003
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-111286
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-118293
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118714
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-116720
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-121669
    cvss: 6.1
    kev_status: "false"
  - id: CVE-2026-116721
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-109500
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120000
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-118707
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-100204
    kev_status: unknown
  - id: CVE-2026-100223
    kev_status: unknown
  - id: CVE-2026-102200
    kev_status: unknown
  - id: CVE-2026-102219
    kev_status: unknown
  - id: CVE-2026-102224
    kev_status: unknown
  - id: CVE-2026-102230
    kev_status: unknown
  - id: CVE-2026-102236
    kev_status: unknown
  - id: CVE-2026-102868
    kev_status: unknown
  - id: CVE-2026-103571
    kev_status: unknown
  - id: CVE-2026-105017
    kev_status: unknown
  - id: CVE-2026-105018
    kev_status: unknown
  - id: CVE-2026-105020
    kev_status: unknown
  - id: CVE-2026-105021
    kev_status: unknown
  - id: CVE-2026-105022
    kev_status: unknown
  - id: CVE-2026-105023
    kev_status: unknown
  - id: CVE-2026-105024
    kev_status: unknown
  - id: CVE-2026-105025
    kev_status: unknown
  - id: CVE-2026-105026
    kev_status: unknown
  - id: CVE-2026-105028
    kev_status: unknown
  - id: CVE-2026-105490
    kev_status: unknown
  - id: CVE-2026-105491
    kev_status: unknown
  - id: CVE-2026-105493
    kev_status: unknown
  - id: CVE-2026-105494
    kev_status: unknown
  - id: CVE-2026-105495
    kev_status: unknown
  - id: CVE-2026-105496
    kev_status: unknown
  - id: CVE-2026-105497
    kev_status: unknown
  - id: CVE-2026-105498
    kev_status: unknown
  - id: CVE-2026-105499
    kev_status: unknown
  - id: CVE-2026-105501
    kev_status: unknown
  - id: CVE-2026-105503
    kev_status: unknown
  - id: CVE-2026-105504
    kev_status: unknown
  - id: CVE-2026-105506
    kev_status: unknown
  - id: CVE-2026-105507
    kev_status: unknown
  - id: CVE-2026-105509
    kev_status: unknown
  - id: CVE-2026-105510
    kev_status: unknown
  - id: CVE-2026-105511
    kev_status: unknown
  - id: CVE-2026-105513
    kev_status: unknown
  - id: CVE-2026-105515
    kev_status: unknown
  - id: CVE-2026-105518
    kev_status: unknown
  - id: CVE-2026-105520
    kev_status: unknown
  - id: CVE-2026-105522
    kev_status: unknown
  - id: CVE-2026-105524
    kev_status: unknown
  - id: CVE-2026-105525
    kev_status: unknown
  - id: CVE-2026-105526
    kev_status: unknown
  - id: CVE-2026-105527
    kev_status: unknown
  - id: CVE-2026-105528
    kev_status: unknown
  - id: CVE-2026-105529
    kev_status: unknown
  - id: CVE-2026-105530
    kev_status: unknown
  - id: CVE-2026-105531
    kev_status: unknown
  - id: CVE-2026-105532
    kev_status: unknown
  - id: CVE-2026-105533
    kev_status: unknown
  - id: CVE-2026-105534
    kev_status: unknown
  - id: CVE-2026-105537
    kev_status: unknown
  - id: CVE-2026-105540
    kev_status: unknown
  - id: CVE-2026-105541
    kev_status: unknown
  - id: CVE-2026-105542
    kev_status: unknown
  - id: CVE-2026-105543
    kev_status: unknown
  - id: CVE-2026-105544
    kev_status: unknown
  - id: CVE-2026-105545
    kev_status: unknown
  - id: CVE-2026-105546
    kev_status: unknown
  - id: CVE-2026-105547
    kev_status: unknown
  - id: CVE-2026-105549
    kev_status: unknown
  - id: CVE-2026-105551
    kev_status: unknown
  - id: CVE-2026-105552
    kev_status: unknown
  - id: CVE-2026-105553
    kev_status: unknown
  - id: CVE-2026-105554
    kev_status: unknown
  - id: CVE-2026-105557
    kev_status: unknown
  - id: CVE-2026-105558
    kev_status: unknown
  - id: CVE-2026-105559
    kev_status: unknown
  - id: CVE-2026-105560
    kev_status: unknown
  - id: CVE-2026-105561
    kev_status: unknown
  - id: CVE-2026-105562
    kev_status: unknown
  - id: CVE-2026-105565
    kev_status: unknown
  - id: CVE-2026-105566
    kev_status: unknown
  - id: CVE-2026-105567
    kev_status: unknown
  - id: CVE-2026-105568
    kev_status: unknown
  - id: CVE-2026-105569
    kev_status: unknown
  - id: CVE-2026-105574
    kev_status: unknown
  - id: CVE-2026-105575
    kev_status: unknown
  - id: CVE-2026-105579
    kev_status: unknown
  - id: CVE-2026-105580
    kev_status: unknown
  - id: CVE-2026-105581
    kev_status: unknown
  - id: CVE-2026-105582
    kev_status: unknown
  - id: CVE-2026-105583
    kev_status: unknown
  - id: CVE-2026-105584
    kev_status: unknown
  - id: CVE-2026-105587
    kev_status: unknown
  - id: CVE-2026-105588
    kev_status: unknown
  - id: CVE-2026-105589
    kev_status: unknown
  - id: CVE-2026-105590
    kev_status: unknown
  - id: CVE-2026-105734
    kev_status: unknown
  - id: CVE-2026-108401
    kev_status: unknown
  - id: CVE-2026-108402
    kev_status: unknown
  - id: CVE-2026-108403
    kev_status: unknown
  - id: CVE-2026-108404
    kev_status: unknown
  - id: CVE-2026-108405
    kev_status: unknown
  - id: CVE-2026-108406
    kev_status: unknown
  - id: CVE-2026-108407
    kev_status: unknown
  - id: CVE-2026-108408
    kev_status: unknown
  - id: CVE-2026-108409
    kev_status: unknown
  - id: CVE-2026-108410
    kev_status: unknown
  - id: CVE-2026-108411
    kev_status: unknown
  - id: CVE-2026-108412
    kev_status: unknown
  - id: CVE-2026-108413
    kev_status: unknown
  - id: CVE-2026-108414
    kev_status: unknown
  - id: CVE-2026-108415
    kev_status: unknown
  - id: CVE-2026-108416
    kev_status: unknown
  - id: CVE-2026-108417
    kev_status: unknown
  - id: CVE-2026-108418
    kev_status: unknown
  - id: CVE-2026-108419
    kev_status: unknown
  - id: CVE-2026-108421
    kev_status: unknown
  - id: CVE-2026-108423
    kev_status: unknown
  - id: CVE-2026-108424
    kev_status: unknown
  - id: CVE-2026-108425
    kev_status: unknown
  - id: CVE-2026-109457
    kev_status: unknown
  - id: CVE-2026-109459
    kev_status: unknown
  - id: CVE-2026-109462
    kev_status: unknown
  - id: CVE-2026-109463
    kev_status: unknown
  - id: CVE-2026-109467
    kev_status: unknown
  - id: CVE-2026-109473
    kev_status: unknown
  - id: CVE-2026-109475
    kev_status: unknown
  - id: CVE-2026-109476
    kev_status: unknown
  - id: CVE-2026-109478
    kev_status: unknown
  - id: CVE-2026-109481
    kev_status: unknown
  - id: CVE-2026-109496
    kev_status: unknown
  - id: CVE-2026-109497
    kev_status: unknown
  - id: CVE-2026-109503
    kev_status: unknown
  - id: CVE-2026-109505
    kev_status: unknown
  - id: CVE-2026-110044
    kev_status: unknown
  - id: CVE-2026-110048
    kev_status: unknown
  - id: CVE-2026-110051
    kev_status: unknown
  - id: CVE-2026-110055
    kev_status: unknown
  - id: CVE-2026-110062
    kev_status: unknown
  - id: CVE-2026-110065
    kev_status: unknown
  - id: CVE-2026-111289
    kev_status: unknown
  - id: CVE-2026-111290
    kev_status: unknown
  - id: CVE-2026-111291
    kev_status: unknown
  - id: CVE-2026-111293
    kev_status: unknown
  - id: CVE-2026-111294
    kev_status: unknown
  - id: CVE-2026-111297
    kev_status: unknown
  - id: CVE-2026-111300
    kev_status: unknown
  - id: CVE-2026-111301
    kev_status: unknown
  - id: CVE-2026-111303
    kev_status: unknown
  - id: CVE-2026-111308
    kev_status: unknown
  - id: CVE-2026-112717
    kev_status: unknown
  - id: CVE-2026-112723
    kev_status: unknown
  - id: CVE-2026-112726
    kev_status: unknown
  - id: CVE-2026-112727
    kev_status: unknown
  - id: CVE-2026-112728
    kev_status: unknown
  - id: CVE-2026-112730
    kev_status: unknown
  - id: CVE-2026-112733
    kev_status: unknown
  - id: CVE-2026-112736
    kev_status: unknown
  - id: CVE-2026-112737
    kev_status: unknown
  - id: CVE-2026-112741
    kev_status: unknown
  - id: CVE-2026-112743
    kev_status: unknown
  - id: CVE-2026-112745
    kev_status: unknown
  - id: CVE-2026-112750
    kev_status: unknown
  - id: CVE-2026-112751
    kev_status: unknown
  - id: CVE-2026-112752
    kev_status: unknown
  - id: CVE-2026-112753
    kev_status: unknown
  - id: CVE-2026-112755
    kev_status: unknown
  - id: CVE-2026-112756
    kev_status: unknown
  - id: CVE-2026-112757
    kev_status: unknown
  - id: CVE-2026-112758
    kev_status: unknown
  - id: CVE-2026-112759
    kev_status: unknown
  - id: CVE-2026-112760
    kev_status: unknown
  - id: CVE-2026-112761
    kev_status: unknown
  - id: CVE-2026-112762
    kev_status: unknown
  - id: CVE-2026-112763
    kev_status: unknown
  - id: CVE-2026-112764
    kev_status: unknown
  - id: CVE-2026-112765
    kev_status: unknown
  - id: CVE-2026-112766
    kev_status: unknown
  - id: CVE-2026-112789
    kev_status: unknown
  - id: CVE-2026-112790
    kev_status: unknown
  - id: CVE-2026-112791
    kev_status: unknown
  - id: CVE-2026-112792
    kev_status: unknown
  - id: CVE-2026-112793
    kev_status: unknown
  - id: CVE-2026-112794
    kev_status: unknown
  - id: CVE-2026-112795
    kev_status: unknown
  - id: CVE-2026-112796
    kev_status: unknown
  - id: CVE-2026-112797
    kev_status: unknown
  - id: CVE-2026-112798
    kev_status: unknown
  - id: CVE-2026-112799
    kev_status: unknown
  - id: CVE-2026-112800
    kev_status: unknown
  - id: CVE-2026-112801
    kev_status: unknown
  - id: CVE-2026-112802
    kev_status: unknown
  - id: CVE-2026-112803
    kev_status: unknown
  - id: CVE-2026-112804
    kev_status: unknown
  - id: CVE-2026-112805
    kev_status: unknown
  - id: CVE-2026-112806
    kev_status: unknown
  - id: CVE-2026-112808
    kev_status: unknown
  - id: CVE-2026-112809
    kev_status: unknown
  - id: CVE-2026-112810
    kev_status: unknown
  - id: CVE-2026-112811
    kev_status: unknown
  - id: CVE-2026-112812
    kev_status: unknown
  - id: CVE-2026-112813
    kev_status: unknown
  - id: CVE-2026-112814
    kev_status: unknown
  - id: CVE-2026-112965
    kev_status: unknown
  - id: CVE-2026-112966
    kev_status: unknown
  - id: CVE-2026-112967
    kev_status: unknown
  - id: CVE-2026-112968
    kev_status: unknown
  - id: CVE-2026-112969
    kev_status: unknown
  - id: CVE-2026-112970
    kev_status: unknown
  - id: CVE-2026-112971
    kev_status: unknown
  - id: CVE-2026-112972
    kev_status: unknown
  - id: CVE-2026-112973
    kev_status: unknown
  - id: CVE-2026-112975
    kev_status: unknown
  - id: CVE-2026-112976
    kev_status: unknown
  - id: CVE-2026-112977
    kev_status: unknown
  - id: CVE-2026-112978
    kev_status: unknown
  - id: CVE-2026-112979
    kev_status: unknown
  - id: CVE-2026-112980
    kev_status: unknown
  - id: CVE-2026-112981
    kev_status: unknown
  - id: CVE-2026-112984
    kev_status: unknown
  - id: CVE-2026-112986
    kev_status: unknown
  - id: CVE-2026-112987
    kev_status: unknown
  - id: CVE-2026-112988
    kev_status: unknown
  - id: CVE-2026-112989
    kev_status: unknown
  - id: CVE-2026-112990
    kev_status: unknown
  - id: CVE-2026-113748
    kev_status: unknown
  - id: CVE-2026-113749
    kev_status: unknown
  - id: CVE-2026-113750
    kev_status: unknown
  - id: CVE-2026-113751
    kev_status: unknown
  - id: CVE-2026-113752
    kev_status: unknown
  - id: CVE-2026-113753
    kev_status: unknown
  - id: CVE-2026-113754
    kev_status: unknown
  - id: CVE-2026-113755
    kev_status: unknown
  - id: CVE-2026-113756
    kev_status: unknown
  - id: CVE-2026-113757
    kev_status: unknown
  - id: CVE-2026-113758
    kev_status: unknown
  - id: CVE-2026-113760
    kev_status: unknown
  - id: CVE-2026-113761
    kev_status: unknown
  - id: CVE-2026-113762
    kev_status: unknown
  - id: CVE-2026-113763
    kev_status: unknown
  - id: CVE-2026-113764
    kev_status: unknown
  - id: CVE-2026-113765
    kev_status: unknown
  - id: CVE-2026-113766
    kev_status: unknown
  - id: CVE-2026-113767
    kev_status: unknown
  - id: CVE-2026-113768
    kev_status: unknown
  - id: CVE-2026-113769
    kev_status: unknown
  - id: CVE-2026-113770
    kev_status: unknown
  - id: CVE-2026-113771
    kev_status: unknown
  - id: CVE-2026-113772
    kev_status: unknown
  - id: CVE-2026-113773
    kev_status: unknown
  - id: CVE-2026-113814
    kev_status: unknown
  - id: CVE-2026-113815
    kev_status: unknown
  - id: CVE-2026-113816
    kev_status: unknown
  - id: CVE-2026-113817
    kev_status: unknown
  - id: CVE-2026-113818
    kev_status: unknown
  - id: CVE-2026-113819
    kev_status: unknown
  - id: CVE-2026-113820
    kev_status: unknown
  - id: CVE-2026-113821
    kev_status: unknown
  - id: CVE-2026-113822
    kev_status: unknown
  - id: CVE-2026-113823
    kev_status: unknown
  - id: CVE-2026-113825
    kev_status: unknown
  - id: CVE-2026-113842
    kev_status: unknown
  - id: CVE-2026-113843
    kev_status: unknown
  - id: CVE-2026-113844
    kev_status: unknown
  - id: CVE-2026-113847
    kev_status: unknown
  - id: CVE-2026-113848
    kev_status: unknown
  - id: CVE-2026-113855
    kev_status: unknown
  - id: CVE-2026-113856
    kev_status: unknown
  - id: CVE-2026-113859
    kev_status: unknown
  - id: CVE-2026-113860
    kev_status: unknown
  - id: CVE-2026-113861
    kev_status: unknown
  - id: CVE-2026-113862
    kev_status: unknown
  - id: CVE-2026-113863
    kev_status: unknown
  - id: CVE-2026-113864
    kev_status: unknown
  - id: CVE-2026-113865
    kev_status: unknown
  - id: CVE-2026-114146
    kev_status: unknown
  - id: CVE-2026-114147
    kev_status: unknown
  - id: CVE-2026-114149
    kev_status: unknown
  - id: CVE-2026-114150
    kev_status: unknown
  - id: CVE-2026-114151
    kev_status: unknown
  - id: CVE-2026-114152
    kev_status: unknown
  - id: CVE-2026-114154
    kev_status: unknown
  - id: CVE-2026-114155
    kev_status: unknown
  - id: CVE-2026-114156
    kev_status: unknown
  - id: CVE-2026-114157
    kev_status: unknown
  - id: CVE-2026-114158
    kev_status: unknown
  - id: CVE-2026-114159
    kev_status: unknown
  - id: CVE-2026-114160
    kev_status: unknown
  - id: CVE-2026-114161
    kev_status: unknown
  - id: CVE-2026-114166
    kev_status: unknown
  - id: CVE-2026-114169
    kev_status: unknown
  - id: CVE-2026-114170
    kev_status: unknown
  - id: CVE-2026-114171
    kev_status: unknown
  - id: CVE-2026-116697
    kev_status: unknown
  - id: CVE-2026-116698
    kev_status: unknown
  - id: CVE-2026-116699
    kev_status: unknown
  - id: CVE-2026-116700
    kev_status: unknown
  - id: CVE-2026-116706
    kev_status: unknown
  - id: CVE-2026-116707
    kev_status: unknown
  - id: CVE-2026-116710
    kev_status: unknown
  - id: CVE-2026-116714
    kev_status: unknown
  - id: CVE-2026-116717
    kev_status: unknown
  - id: CVE-2026-116719
    kev_status: unknown
  - id: CVE-2026-116722
    kev_status: unknown
  - id: CVE-2026-116922
    kev_status: unknown
  - id: CVE-2026-116923
    kev_status: unknown
  - id: CVE-2026-116926
    kev_status: unknown
  - id: CVE-2026-116929
    kev_status: unknown
  - id: CVE-2026-116930
    kev_status: unknown
  - id: CVE-2026-116931
    kev_status: unknown
  - id: CVE-2026-116932
    kev_status: unknown
  - id: CVE-2026-116933
    kev_status: unknown
  - id: CVE-2026-116934
    kev_status: unknown
  - id: CVE-2026-116935
    kev_status: unknown
  - id: CVE-2026-116936
    kev_status: unknown
  - id: CVE-2026-116937
    kev_status: unknown
  - id: CVE-2026-116938
    kev_status: unknown
  - id: CVE-2026-116939
    kev_status: unknown
  - id: CVE-2026-116940
    kev_status: unknown
  - id: CVE-2026-116941
    kev_status: unknown
  - id: CVE-2026-116942
    kev_status: unknown
  - id: CVE-2026-116943
    kev_status: unknown
  - id: CVE-2026-116944
    kev_status: unknown
  - id: CVE-2026-116945
    kev_status: unknown
  - id: CVE-2026-116946
    kev_status: unknown
  - id: CVE-2026-116947
    kev_status: unknown
  - id: CVE-2026-118102
    kev_status: unknown
  - id: CVE-2026-118103
    kev_status: unknown
  - id: CVE-2026-118104
    kev_status: unknown
  - id: CVE-2026-118105
    kev_status: unknown
  - id: CVE-2026-118106
    kev_status: unknown
  - id: CVE-2026-118108
    kev_status: unknown
  - id: CVE-2026-118109
    kev_status: unknown
  - id: CVE-2026-118110
    kev_status: unknown
  - id: CVE-2026-118111
    kev_status: unknown
  - id: CVE-2026-118112
    kev_status: unknown
  - id: CVE-2026-118113
    kev_status: unknown
  - id: CVE-2026-118114
    kev_status: unknown
  - id: CVE-2026-118115
    kev_status: unknown
  - id: CVE-2026-118116
    kev_status: unknown
  - id: CVE-2026-118117
    kev_status: unknown
  - id: CVE-2026-118118
    kev_status: unknown
  - id: CVE-2026-118119
    kev_status: unknown
  - id: CVE-2026-118120
    kev_status: unknown
  - id: CVE-2026-118123
    kev_status: unknown
  - id: CVE-2026-118124
    kev_status: unknown
  - id: CVE-2026-118125
    kev_status: unknown
  - id: CVE-2026-118126
    kev_status: unknown
  - id: CVE-2026-118137
    kev_status: unknown
  - id: CVE-2026-118138
    kev_status: unknown
  - id: CVE-2026-118140
    kev_status: unknown
  - id: CVE-2026-118141
    kev_status: unknown
  - id: CVE-2026-118142
    kev_status: unknown
  - id: CVE-2026-118143
    kev_status: unknown
  - id: CVE-2026-118144
    kev_status: unknown
  - id: CVE-2026-118145
    kev_status: unknown
  - id: CVE-2026-118146
    kev_status: unknown
  - id: CVE-2026-118148
    kev_status: unknown
  - id: CVE-2026-118151
    kev_status: unknown
  - id: CVE-2026-118153
    kev_status: unknown
  - id: CVE-2026-118154
    kev_status: unknown
  - id: CVE-2026-118157
    kev_status: unknown
  - id: CVE-2026-118213
    kev_status: unknown
  - id: CVE-2026-118214
    kev_status: unknown
  - id: CVE-2026-118215
    kev_status: unknown
  - id: CVE-2026-118216
    kev_status: unknown
  - id: CVE-2026-118217
    kev_status: unknown
  - id: CVE-2026-118218
    kev_status: unknown
  - id: CVE-2026-118219
    kev_status: unknown
  - id: CVE-2026-118220
    kev_status: unknown
  - id: CVE-2026-118221
    kev_status: unknown
  - id: CVE-2026-118222
    kev_status: unknown
  - id: CVE-2026-118223
    kev_status: unknown
  - id: CVE-2026-118224
    kev_status: unknown
  - id: CVE-2026-118225
    kev_status: unknown
  - id: CVE-2026-118226
    kev_status: unknown
  - id: CVE-2026-118227
    kev_status: unknown
  - id: CVE-2026-118228
    kev_status: unknown
  - id: CVE-2026-118229
    kev_status: unknown
  - id: CVE-2026-118232
    kev_status: unknown
  - id: CVE-2026-118277
    kev_status: unknown
  - id: CVE-2026-118278
    kev_status: unknown
  - id: CVE-2026-118279
    kev_status: unknown
  - id: CVE-2026-118280
    kev_status: unknown
  - id: CVE-2026-118283
    kev_status: unknown
  - id: CVE-2026-118288
    kev_status: unknown
  - id: CVE-2026-118292
    kev_status: unknown
  - id: CVE-2026-118294
    kev_status: unknown
  - id: CVE-2026-118295
    kev_status: unknown
  - id: CVE-2026-118296
    kev_status: unknown
  - id: CVE-2026-118297
    kev_status: unknown
  - id: CVE-2026-118299
    kev_status: unknown
  - id: CVE-2026-118300
    kev_status: unknown
  - id: CVE-2026-118301
    kev_status: unknown
  - id: CVE-2026-118302
    kev_status: unknown
  - id: CVE-2026-118700
    kev_status: unknown
  - id: CVE-2026-118701
    kev_status: unknown
  - id: CVE-2026-118702
    kev_status: unknown
  - id: CVE-2026-118703
    kev_status: unknown
  - id: CVE-2026-118704
    kev_status: unknown
  - id: CVE-2026-118705
    kev_status: unknown
  - id: CVE-2026-118706
    kev_status: unknown
  - id: CVE-2026-118708
    kev_status: unknown
  - id: CVE-2026-118710
    kev_status: unknown
  - id: CVE-2026-118711
    kev_status: unknown
  - id: CVE-2026-118712
    kev_status: unknown
  - id: CVE-2026-118713
    kev_status: unknown
  - id: CVE-2026-118715
    kev_status: unknown
  - id: CVE-2026-118716
    kev_status: unknown
  - id: CVE-2026-118717
    kev_status: unknown
  - id: CVE-2026-118719
    kev_status: unknown
  - id: CVE-2026-118720
    kev_status: unknown
  - id: CVE-2026-118721
    kev_status: unknown
  - id: CVE-2026-118722
    kev_status: unknown
  - id: CVE-2026-118724
    kev_status: unknown
  - id: CVE-2026-118725
    kev_status: unknown
  - id: CVE-2026-118726
    kev_status: unknown
  - id: CVE-2026-118727
    kev_status: unknown
  - id: CVE-2026-118728
    kev_status: unknown
  - id: CVE-2026-118729
    kev_status: unknown
  - id: CVE-2026-118730
    kev_status: unknown
  - id: CVE-2026-118731
    kev_status: unknown
  - id: CVE-2026-118732
    kev_status: unknown
  - id: CVE-2026-118735
    kev_status: unknown
  - id: CVE-2026-118736
    kev_status: unknown
  - id: CVE-2026-118737
    kev_status: unknown
  - id: CVE-2026-118739
    kev_status: unknown
  - id: CVE-2026-118741
    kev_status: unknown
  - id: CVE-2026-118742
    kev_status: unknown
  - id: CVE-2026-118745
    kev_status: unknown
  - id: CVE-2026-118746
    kev_status: unknown
  - id: CVE-2026-118747
    kev_status: unknown
  - id: CVE-2026-118748
    kev_status: unknown
  - id: CVE-2026-118749
    kev_status: unknown
  - id: CVE-2026-118750
    kev_status: unknown
  - id: CVE-2026-119382
    kev_status: unknown
  - id: CVE-2026-119383
    kev_status: unknown
  - id: CVE-2026-119385
    kev_status: unknown
  - id: CVE-2026-119386
    kev_status: unknown
  - id: CVE-2026-119387
    kev_status: unknown
  - id: CVE-2026-119388
    kev_status: unknown
  - id: CVE-2026-119389
    kev_status: unknown
  - id: CVE-2026-119390
    kev_status: unknown
  - id: CVE-2026-119391
    kev_status: unknown
  - id: CVE-2026-119392
    kev_status: unknown
  - id: CVE-2026-119393
    kev_status: unknown
  - id: CVE-2026-119394
    kev_status: unknown
  - id: CVE-2026-119395
    kev_status: unknown
  - id: CVE-2026-119396
    kev_status: unknown
  - id: CVE-2026-119397
    kev_status: unknown
  - id: CVE-2026-119398
    kev_status: unknown
  - id: CVE-2026-119399
    kev_status: unknown
  - id: CVE-2026-119401
    kev_status: unknown
  - id: CVE-2026-119402
    kev_status: unknown
  - id: CVE-2026-119403
    kev_status: unknown
  - id: CVE-2026-119404
    kev_status: unknown
  - id: CVE-2026-119405
    kev_status: unknown
  - id: CVE-2026-119817
    kev_status: unknown
  - id: CVE-2026-119818
    kev_status: unknown
  - id: CVE-2026-119821
    kev_status: unknown
  - id: CVE-2026-119822
    kev_status: unknown
  - id: CVE-2026-119823
    kev_status: unknown
  - id: CVE-2026-119824
    kev_status: unknown
  - id: CVE-2026-119825
    kev_status: unknown
  - id: CVE-2026-119826
    kev_status: unknown
  - id: CVE-2026-119827
    kev_status: unknown
  - id: CVE-2026-119829
    kev_status: unknown
  - id: CVE-2026-119830
    kev_status: unknown
  - id: CVE-2026-119831
    kev_status: unknown
  - id: CVE-2026-119832
    kev_status: unknown
  - id: CVE-2026-119833
    kev_status: unknown
  - id: CVE-2026-119834
    kev_status: unknown
  - id: CVE-2026-119835
    kev_status: unknown
  - id: CVE-2026-119836
    kev_status: unknown
  - id: CVE-2026-119837
    kev_status: unknown
  - id: CVE-2026-119838
    kev_status: unknown
  - id: CVE-2026-119839
    kev_status: unknown
  - id: CVE-2026-119840
    kev_status: unknown
  - id: CVE-2026-119841
    kev_status: unknown
  - id: CVE-2026-119844
    kev_status: unknown
  - id: CVE-2026-119846
    kev_status: unknown
  - id: CVE-2026-119847
    kev_status: unknown
  - id: CVE-2026-119848
    kev_status: unknown
  - id: CVE-2026-119849
    kev_status: unknown
  - id: CVE-2026-119851
    kev_status: unknown
  - id: CVE-2026-119852
    kev_status: unknown
  - id: CVE-2026-119853
    kev_status: unknown
  - id: CVE-2026-119855
    kev_status: unknown
  - id: CVE-2026-119856
    kev_status: unknown
  - id: CVE-2026-119857
    kev_status: unknown
  - id: CVE-2026-119858
    kev_status: unknown
  - id: CVE-2026-119859
    kev_status: unknown
  - id: CVE-2026-119860
    kev_status: unknown
  - id: CVE-2026-119861
    kev_status: unknown
  - id: CVE-2026-119862
    kev_status: unknown
  - id: CVE-2026-119865
    kev_status: unknown
  - id: CVE-2026-119866
    kev_status: unknown
  - id: CVE-2026-119867
    kev_status: unknown
  - id: CVE-2026-119868
    kev_status: unknown
  - id: CVE-2026-119869
    kev_status: unknown
  - id: CVE-2026-119870
    kev_status: unknown
  - id: CVE-2026-119871
    kev_status: unknown
  - id: CVE-2026-119872
    kev_status: unknown
  - id: CVE-2026-119873
    kev_status: unknown
  - id: CVE-2026-119874
    kev_status: unknown
  - id: CVE-2026-119875
    kev_status: unknown
  - id: CVE-2026-119876
    kev_status: unknown
  - id: CVE-2026-119881
    kev_status: unknown
  - id: CVE-2026-119882
    kev_status: unknown
  - id: CVE-2026-119883
    kev_status: unknown
  - id: CVE-2026-119884
    kev_status: unknown
  - id: CVE-2026-119885
    kev_status: unknown
  - id: CVE-2026-119886
    kev_status: unknown
  - id: CVE-2026-119887
    kev_status: unknown
  - id: CVE-2026-119888
    kev_status: unknown
  - id: CVE-2026-119889
    kev_status: unknown
  - id: CVE-2026-119890
    kev_status: unknown
  - id: CVE-2026-119892
    kev_status: unknown
  - id: CVE-2026-119893
    kev_status: unknown
  - id: CVE-2026-119894
    kev_status: unknown
  - id: CVE-2026-119895
    kev_status: unknown
  - id: CVE-2026-119898
    kev_status: unknown
  - id: CVE-2026-119899
    kev_status: unknown
  - id: CVE-2026-119900
    kev_status: unknown
  - id: CVE-2026-119901
    kev_status: unknown
  - id: CVE-2026-119903
    kev_status: unknown
  - id: CVE-2026-119904
    kev_status: unknown
  - id: CVE-2026-119905
    kev_status: unknown
  - id: CVE-2026-119906
    kev_status: unknown
  - id: CVE-2026-119907
    kev_status: unknown
  - id: CVE-2026-119908
    kev_status: unknown
  - id: CVE-2026-119909
    kev_status: unknown
  - id: CVE-2026-119910
    kev_status: unknown
  - id: CVE-2026-119912
    kev_status: unknown
  - id: CVE-2026-119913
    kev_status: unknown
  - id: CVE-2026-119914
    kev_status: unknown
  - id: CVE-2026-119916
    kev_status: unknown
  - id: CVE-2026-119917
    kev_status: unknown
  - id: CVE-2026-119918
    kev_status: unknown
  - id: CVE-2026-119919
    kev_status: unknown
  - id: CVE-2026-119921
    kev_status: unknown
  - id: CVE-2026-119925
    kev_status: unknown
  - id: CVE-2026-119928
    kev_status: unknown
  - id: CVE-2026-119929
    kev_status: unknown
  - id: CVE-2026-119931
    kev_status: unknown
  - id: CVE-2026-119932
    kev_status: unknown
  - id: CVE-2026-119933
    kev_status: unknown
  - id: CVE-2026-119934
    kev_status: unknown
  - id: CVE-2026-119935
    kev_status: unknown
  - id: CVE-2026-119936
    kev_status: unknown
  - id: CVE-2026-119938
    kev_status: unknown
  - id: CVE-2026-119939
    kev_status: unknown
  - id: CVE-2026-119940
    kev_status: unknown
  - id: CVE-2026-119941
    kev_status: unknown
  - id: CVE-2026-119942
    kev_status: unknown
  - id: CVE-2026-119944
    kev_status: unknown
  - id: CVE-2026-119945
    kev_status: unknown
  - id: CVE-2026-119946
    kev_status: unknown
  - id: CVE-2026-119947
    kev_status: unknown
  - id: CVE-2026-119948
    kev_status: unknown
  - id: CVE-2026-119950
    kev_status: unknown
  - id: CVE-2026-119951
    kev_status: unknown
  - id: CVE-2026-119952
    kev_status: unknown
  - id: CVE-2026-119953
    kev_status: unknown
  - id: CVE-2026-119954
    kev_status: unknown
  - id: CVE-2026-119955
    kev_status: unknown
  - id: CVE-2026-119957
    kev_status: unknown
  - id: CVE-2026-119958
    kev_status: unknown
  - id: CVE-2026-119959
    kev_status: unknown
  - id: CVE-2026-119960
    kev_status: unknown
  - id: CVE-2026-119961
    kev_status: unknown
  - id: CVE-2026-119962
    kev_status: unknown
  - id: CVE-2026-119963
    kev_status: unknown
  - id: CVE-2026-119964
    kev_status: unknown
  - id: CVE-2026-119965
    kev_status: unknown
  - id: CVE-2026-119966
    kev_status: unknown
  - id: CVE-2026-119967
    kev_status: unknown
  - id: CVE-2026-119969
    kev_status: unknown
  - id: CVE-2026-119970
    kev_status: unknown
  - id: CVE-2026-119971
    kev_status: unknown
  - id: CVE-2026-119972
    kev_status: unknown
  - id: CVE-2026-119974
    kev_status: unknown
  - id: CVE-2026-119975
    kev_status: unknown
  - id: CVE-2026-119976
    kev_status: unknown
  - id: CVE-2026-119981
    kev_status: unknown
  - id: CVE-2026-119982
    kev_status: unknown
  - id: CVE-2026-119983
    kev_status: unknown
  - id: CVE-2026-119985
    kev_status: unknown
  - id: CVE-2026-119988
    kev_status: unknown
  - id: CVE-2026-119989
    kev_status: unknown
  - id: CVE-2026-119990
    kev_status: unknown
  - id: CVE-2026-119992
    kev_status: unknown
  - id: CVE-2026-119993
    kev_status: unknown
  - id: CVE-2026-119995
    kev_status: unknown
  - id: CVE-2026-119996
    kev_status: unknown
  - id: CVE-2026-119997
    kev_status: unknown
  - id: CVE-2026-119998
    kev_status: unknown
  - id: CVE-2026-119999
    kev_status: unknown
  - id: CVE-2026-120001
    kev_status: unknown
  - id: CVE-2026-120005
    kev_status: unknown
  - id: CVE-2026-120006
    kev_status: unknown
  - id: CVE-2026-120778
    kev_status: unknown
  - id: CVE-2026-120779
    kev_status: unknown
  - id: CVE-2026-120780
    kev_status: unknown
  - id: CVE-2026-120782
    kev_status: unknown
  - id: CVE-2026-120783
    kev_status: unknown
  - id: CVE-2026-120788
    kev_status: unknown
  - id: CVE-2026-120792
    kev_status: unknown
  - id: CVE-2026-120796
    kev_status: unknown
  - id: CVE-2026-121660
    kev_status: unknown
  - id: CVE-2026-121661
    kev_status: unknown
  - id: CVE-2026-121662
    kev_status: unknown
  - id: CVE-2026-121663
    kev_status: unknown
  - id: CVE-2026-121664
    kev_status: unknown
  - id: CVE-2026-121665
    kev_status: unknown
  - id: CVE-2026-121668
    kev_status: unknown
  - id: CVE-2026-121670
    kev_status: unknown
  - id: CVE-2026-121671
    kev_status: unknown
  - id: CVE-2026-121673
    kev_status: unknown
  - id: CVE-2026-121675
    kev_status: unknown
  - id: CVE-2026-121677
    kev_status: unknown
  - id: CVE-2026-121678
    kev_status: unknown
  - id: CVE-2026-121680
    kev_status: unknown
  - id: CVE-2026-121681
    kev_status: unknown
  - id: CVE-2026-122162
    kev_status: unknown
  - id: CVE-2026-122163
    kev_status: unknown
  - id: CVE-2026-122164
    kev_status: unknown
  - id: CVE-2026-122165
    kev_status: unknown
  - id: CVE-2026-122166
    kev_status: unknown
  - id: CVE-2026-122167
    kev_status: unknown
  - id: CVE-2026-122168
    kev_status: unknown
  - id: CVE-2026-122169
    kev_status: unknown
  - id: CVE-2026-122170
    kev_status: unknown
  - id: CVE-2026-122171
    kev_status: unknown
  - id: CVE-2026-122173
    kev_status: unknown
  - id: CVE-2026-122174
    kev_status: unknown
  - id: CVE-2026-122175
    kev_status: unknown
  - id: CVE-2026-122176
    kev_status: unknown
  - id: CVE-2026-122177
    kev_status: unknown
  - id: CVE-2026-122179
    kev_status: unknown
  - id: CVE-2026-122182
    kev_status: unknown
  - id: CVE-2026-122183
    kev_status: unknown
  - id: CVE-2026-122198
    kev_status: unknown
  - id: CVE-2026-122297
    kev_status: unknown
  - id: CVE-2026-122474
    kev_status: unknown
  - id: CVE-2026-122475
    kev_status: unknown
  - id: CVE-2026-122984
    kev_status: unknown
  - id: CVE-2026-122985
    kev_status: unknown
  - id: CVE-2026-122986
    kev_status: unknown
  - id: CVE-2026-122988
    kev_status: unknown
  - id: CVE-2026-123377
    kev_status: unknown
  - id: CVE-2026-123379
    kev_status: unknown
  - id: CVE-2026-123381
    kev_status: unknown
  - id: CVE-2026-123382
    kev_status: unknown
  - id: CVE-2026-123385
    kev_status: unknown
  - id: CVE-2026-123387
    kev_status: unknown
  - id: CVE-2026-123388
    kev_status: unknown
  - id: CVE-2026-123389
    kev_status: unknown
  - id: CVE-2026-123390
    kev_status: unknown
  - id: CVE-2026-123394
    kev_status: unknown
  - id: CVE-2026-123395
    kev_status: unknown
  - id: CVE-2026-124170
    kev_status: unknown
  - id: CVE-2026-124176
    kev_status: unknown
  - id: CVE-2026-124178
    kev_status: unknown
  - id: CVE-2026-124183
    kev_status: unknown
  - id: CVE-2026-124210
    kev_status: unknown
  - id: CVE-2026-124224
    kev_status: unknown
  - id: CVE-2026-124225
    kev_status: unknown
  - id: CVE-2026-124226
    kev_status: unknown
  - id: CVE-2026-124229
    kev_status: unknown
  - id: CVE-2026-125134
    kev_status: unknown
  - id: CVE-2026-125135
    kev_status: unknown
  - id: CVE-2026-125136
    kev_status: unknown
  - id: CVE-2026-125137
    kev_status: unknown
  - id: CVE-2026-62903
    kev_status: unknown
  - id: CVE-2026-66801
    kev_status: unknown
  - id: CVE-2026-66813
    kev_status: unknown
  - id: CVE-2026-67372
    kev_status: unknown
  - id: CVE-2026-67374
    kev_status: unknown
  - id: CVE-2026-67375
    kev_status: unknown
  - id: CVE-2026-67382
    kev_status: unknown
  - id: CVE-2026-67387
    kev_status: unknown
  - id: CVE-2026-67391
    kev_status: unknown
  - id: CVE-2026-67632
    kev_status: unknown
  - id: CVE-2026-67637
    kev_status: unknown
  - id: CVE-2026-67646
    kev_status: unknown
  - id: CVE-2026-68783
    kev_status: unknown
  - id: CVE-2026-69327
    kev_status: unknown
  - id: CVE-2026-69565
    kev_status: unknown
  - id: CVE-2026-70003
    kev_status: unknown
  - id: CVE-2026-70094
    kev_status: unknown
  - id: CVE-2026-70182
    kev_status: unknown
  - id: CVE-2026-70231
    kev_status: unknown
  - id: CVE-2026-70240
    kev_status: unknown
  - id: CVE-2026-72998
    kev_status: unknown
  - id: CVE-2026-80094
    kev_status: unknown
  - id: CVE-2026-81384
    kev_status: unknown
  - id: CVE-2026-83563
    kev_status: unknown
  - id: CVE-2026-83684
    kev_status: unknown
  - id: CVE-2026-83894
    kev_status: unknown
  - id: CVE-2026-84010
    kev_status: unknown
  - id: CVE-2026-85801
    kev_status: unknown
  - id: CVE-2026-85844
    kev_status: unknown
  - id: CVE-2026-85862
    kev_status: unknown
  - id: CVE-2026-85907
    kev_status: unknown
  - id: CVE-2026-85923
    kev_status: unknown
  - id: CVE-2026-85929
    kev_status: unknown
  - id: CVE-2026-85942
    kev_status: unknown
  - id: CVE-2026-88111
    kev_status: unknown
  - id: CVE-2026-88187
    kev_status: unknown
  - id: CVE-2026-88211
    kev_status: unknown
  - id: CVE-2026-88212
    kev_status: unknown
  - id: CVE-2026-88213
    kev_status: unknown
  - id: CVE-2026-88215
    kev_status: unknown
  - id: CVE-2026-88216
    kev_status: unknown
  - id: CVE-2026-88217
    kev_status: unknown
  - id: CVE-2026-88218
    kev_status: unknown
  - id: CVE-2026-88220
    kev_status: unknown
  - id: CVE-2026-88221
    kev_status: unknown
  - id: CVE-2026-88224
    kev_status: unknown
  - id: CVE-2026-88227
    kev_status: unknown
  - id: CVE-2026-88228
    kev_status: unknown
  - id: CVE-2026-88229
    kev_status: unknown
  - id: CVE-2026-88230
    kev_status: unknown
  - id: CVE-2026-88231
    kev_status: unknown
  - id: CVE-2026-88232
    kev_status: unknown
  - id: CVE-2026-88233
    kev_status: unknown
  - id: CVE-2026-88234
    kev_status: unknown
  - id: CVE-2026-88235
    kev_status: unknown
  - id: CVE-2026-88237
    kev_status: unknown
  - id: CVE-2026-88238
    kev_status: unknown
  - id: CVE-2026-88239
    kev_status: unknown
  - id: CVE-2026-88240
    kev_status: unknown
  - id: CVE-2026-88241
    kev_status: unknown
  - id: CVE-2026-88242
    kev_status: unknown
  - id: CVE-2026-88243
    kev_status: unknown
  - id: CVE-2026-88244
    kev_status: unknown
  - id: CVE-2026-88245
    kev_status: unknown
  - id: CVE-2026-88247
    kev_status: unknown
  - id: CVE-2026-88249
    kev_status: unknown
  - id: CVE-2026-94507
    kev_status: unknown
  - id: CVE-2026-94511
    kev_status: unknown
  - id: CVE-2026-94513
    kev_status: unknown
  - id: CVE-2026-94514
    kev_status: unknown
  - id: CVE-2026-94515
    kev_status: unknown
  - id: CVE-2026-94517
    kev_status: unknown
  - id: CVE-2026-94519
    kev_status: unknown
  - id: CVE-2026-94522
    kev_status: unknown
  - id: CVE-2026-94525
    kev_status: unknown
  - id: CVE-2026-94527
    kev_status: unknown
  - id: CVE-2026-94529
    kev_status: unknown
  - id: CVE-2026-94531
    kev_status: unknown
  - id: CVE-2026-95871
    kev_status: unknown
  - id: CVE-2026-95872
    kev_status: unknown
  - id: CVE-2026-95874
    kev_status: unknown
  - id: CVE-2026-95876
    kev_status: unknown
  - id: CVE-2026-95877
    kev_status: unknown
  - id: CVE-2026-95879
    kev_status: unknown
  - id: CVE-2026-95881
    kev_status: unknown
  - id: CVE-2026-95884
    kev_status: unknown
  - id: CVE-2026-95885
    kev_status: unknown
  - id: CVE-2026-95888
    kev_status: unknown
  - id: CVE-2026-95889
    kev_status: unknown
  - id: CVE-2026-95893
    kev_status: unknown
  - id: CVE-2026-95894
    kev_status: unknown
  - id: CVE-2026-95895
    kev_status: unknown
  - id: CVE-2026-95898
    kev_status: unknown
  - id: CVE-2026-95902
    kev_status: unknown
  - id: CVE-2026-95905
    kev_status: unknown
  - id: CVE-2026-95906
    kev_status: unknown
  - id: CVE-2026-95908
    kev_status: unknown
  - id: CVE-2026-95909
    kev_status: unknown
  - id: CVE-2026-95910
    kev_status: unknown
  - id: CVE-2026-95913
    kev_status: unknown
  - id: CVE-2026-95920
    kev_status: unknown
  - id: CVE-2026-95922
    kev_status: "false"
  - id: CVE-2026-95923
    kev_status: unknown
  - id: CVE-2026-95932
    kev_status: unknown
  - id: CVE-2026-95933
    kev_status: unknown
  - id: CVE-2026-95934
    kev_status: unknown
  - id: CVE-2026-95935
    kev_status: unknown
  - id: CVE-2026-95938
    kev_status: unknown
  - id: CVE-2026-95942
    kev_status: unknown
  - id: CVE-2026-95944
    kev_status: unknown
  - id: CVE-2026-95946
    kev_status: unknown
  - id: CVE-2026-95947
    kev_status: unknown
  - id: CVE-2026-95948
    kev_status: unknown
  - id: CVE-2026-95950
    kev_status: unknown
  - id: CVE-2026-95951
    kev_status: unknown
  - id: CVE-2026-95953
    kev_status: unknown
  - id: CVE-2026-95956
    kev_status: unknown
  - id: CVE-2026-95960
    kev_status: unknown
  - id: CVE-2026-95961
    kev_status: unknown
  - id: CVE-2026-95962
    kev_status: unknown
  - id: CVE-2026-95963
    kev_status: unknown
  - id: CVE-2026-95964
    kev_status: unknown
  - id: CVE-2026-95965
    kev_status: unknown
  - id: CVE-2026-95966
    kev_status: unknown
  - id: CVE-2026-95968
    kev_status: unknown
  - id: CVE-2026-95971
    kev_status: unknown
  - id: CVE-2026-95973
    kev_status: unknown
  - id: CVE-2026-95974
    kev_status: unknown
  - id: CVE-2026-95975
    kev_status: unknown
  - id: CVE-2026-95976
    kev_status: unknown
  - id: CVE-2026-95977
    kev_status: unknown
  - id: CVE-2026-95979
    kev_status: unknown
  - id: CVE-2026-95983
    kev_status: unknown
  - id: CVE-2026-95987
    kev_status: unknown
  - id: CVE-2026-95988
    kev_status: unknown
  - id: CVE-2026-95989
    kev_status: unknown
  - id: CVE-2026-95991
    kev_status: unknown
  - id: CVE-2026-95996
    kev_status: unknown
  - id: CVE-2026-95997
    kev_status: unknown
  - id: CVE-2026-95998
    kev_status: unknown
  - id: CVE-2026-95999
    kev_status: unknown
  - id: CVE-2026-96001
    kev_status: unknown
  - id: CVE-2026-96002
    kev_status: unknown
  - id: CVE-2026-96004
    kev_status: unknown
  - id: CVE-2026-96005
    kev_status: unknown
  - id: CVE-2026-96007
    kev_status: unknown
  - id: CVE-2026-96008
    kev_status: unknown
  - id: CVE-2026-96010
    kev_status: unknown
  - id: CVE-2026-96016
    kev_status: unknown
  - id: CVE-2026-96017
    kev_status: unknown
  - id: CVE-2026-96018
    kev_status: unknown
  - id: CVE-2026-96019
    kev_status: unknown
  - id: CVE-2026-96020
    kev_status: unknown
  - id: CVE-2026-96022
    kev_status: unknown
  - id: CVE-2026-96023
    kev_status: unknown
  - id: CVE-2026-96026
    kev_status: unknown
  - id: CVE-2026-96027
    kev_status: unknown
  - id: CVE-2026-96028
    kev_status: unknown
  - id: CVE-2026-96029
    kev_status: unknown
  - id: CVE-2026-96031
    kev_status: unknown
  - id: CVE-2026-96035
    kev_status: unknown
  - id: CVE-2026-96036
    kev_status: unknown
  - id: CVE-2026-96037
    kev_status: unknown
  - id: CVE-2026-96038
    kev_status: unknown
  - id: CVE-2026-96041
    kev_status: unknown
  - id: CVE-2026-96042
    kev_status: unknown
  - id: CVE-2026-96043
    kev_status: unknown
  - id: CVE-2026-96046
    kev_status: unknown
  - id: CVE-2026-96047
    kev_status: unknown
  - id: CVE-2026-96048
    kev_status: unknown
  - id: CVE-2026-96051
    kev_status: unknown
  - id: CVE-2026-96052
    kev_status: unknown
  - id: CVE-2026-96053
    kev_status: unknown
  - id: CVE-2026-96055
    kev_status: unknown
  - id: CVE-2026-96056
    kev_status: unknown
  - id: CVE-2026-96057
    kev_status: unknown
  - id: CVE-2026-96058
    kev_status: unknown
  - id: CVE-2026-96059
    kev_status: unknown
  - id: CVE-2026-96060
    kev_status: unknown
  - id: CVE-2026-96061
    kev_status: unknown
  - id: CVE-2026-96062
    kev_status: unknown
  - id: CVE-2026-96064
    kev_status: unknown
  - id: CVE-2026-96066
    kev_status: unknown
  - id: CVE-2026-96072
    kev_status: unknown
  - id: CVE-2026-96073
    kev_status: unknown
  - id: CVE-2026-96074
    kev_status: unknown
  - id: CVE-2026-96075
    kev_status: unknown
  - id: CVE-2026-96076
    kev_status: unknown
  - id: CVE-2026-96077
    kev_status: unknown
  - id: CVE-2026-96081
    kev_status: unknown
  - id: CVE-2026-96082
    kev_status: unknown
  - id: CVE-2026-96084
    kev_status: unknown
  - id: CVE-2026-96085
    kev_status: unknown
  - id: CVE-2026-96086
    kev_status: unknown
  - id: CVE-2026-96088
    kev_status: unknown
  - id: CVE-2026-96092
    kev_status: unknown
  - id: CVE-2026-96093
    kev_status: unknown
  - id: CVE-2026-96097
    kev_status: unknown
  - id: CVE-2026-96101
    kev_status: unknown
  - id: CVE-2026-96102
    kev_status: unknown
  - id: CVE-2026-96103
    kev_status: unknown
  - id: CVE-2026-96107
    kev_status: unknown
  - id: CVE-2026-96110
    kev_status: unknown
  - id: CVE-2026-96112
    kev_status: unknown
  - id: CVE-2026-96115
    kev_status: unknown
  - id: CVE-2026-96117
    kev_status: unknown
  - id: CVE-2026-96122
    kev_status: unknown
  - id: CVE-2026-96124
    kev_status: unknown
  - id: CVE-2026-96126
    kev_status: unknown
  - id: CVE-2026-96127
    kev_status: unknown
  - id: CVE-2026-96129
    kev_status: unknown
  - id: CVE-2026-96133
    kev_status: unknown
  - id: CVE-2026-96134
    kev_status: unknown
  - id: CVE-2026-96137
    kev_status: unknown
  - id: CVE-2026-96139
    kev_status: unknown
  - id: CVE-2026-96144
    kev_status: unknown
  - id: CVE-2026-96152
    kev_status: unknown
  - id: CVE-2026-96153
    kev_status: unknown
  - id: CVE-2026-96155
    kev_status: unknown
  - id: CVE-2026-96156
    kev_status: unknown
  - id: CVE-2026-96160
    kev_status: unknown
  - id: CVE-2026-96162
    kev_status: unknown
  - id: CVE-2026-96164
    kev_status: unknown
  - id: CVE-2026-96168
    kev_status: unknown
  - id: CVE-2026-96171
    kev_status: unknown
  - id: CVE-2026-96172
    kev_status: unknown
  - id: CVE-2026-96174
    kev_status: unknown
  - id: CVE-2026-96175
    kev_status: unknown
  - id: CVE-2026-96176
    kev_status: unknown
  - id: CVE-2026-96177
    kev_status: unknown
  - id: CVE-2026-96179
    kev_status: unknown
  - id: CVE-2026-96184
    kev_status: unknown
  - id: CVE-2026-96845
    kev_status: unknown
  - id: CVE-2026-96965
    kev_status: unknown
  - id: CVE-2026-96969
    kev_status: unknown
  - id: CVE-2026-96970
    kev_status: unknown
  - id: CVE-2026-96971
    kev_status: unknown
  - id: CVE-2026-96972
    kev_status: unknown
  - id: CVE-2026-96973
    kev_status: unknown
  - id: CVE-2026-96974
    kev_status: unknown
  - id: CVE-2026-96975
    kev_status: unknown
  - id: CVE-2026-96976
    kev_status: unknown
  - id: CVE-2026-96978
    kev_status: unknown
  - id: CVE-2026-96979
    kev_status: unknown
  - id: CVE-2026-96980
    kev_status: unknown
  - id: CVE-2026-96981
    kev_status: unknown
  - id: CVE-2026-96982
    kev_status: unknown
  - id: CVE-2026-96983
    kev_status: unknown
  - id: CVE-2026-96984
    kev_status: unknown
  - id: CVE-2026-96985
    kev_status: unknown
  - id: CVE-2026-96986
    kev_status: unknown
  - id: CVE-2026-96987
    kev_status: unknown
  - id: CVE-2026-96988
    kev_status: unknown
  - id: CVE-2026-96989
    kev_status: unknown
  - id: CVE-2026-96992
    kev_status: unknown
  - id: CVE-2026-96993
    kev_status: unknown
  - id: CVE-2026-96994
    kev_status: unknown
  - id: CVE-2026-97000
    kev_status: unknown
  - id: CVE-2026-97002
    kev_status: unknown
  - id: CVE-2026-97006
    kev_status: unknown
  - id: CVE-2026-97013
    kev_status: unknown
  - id: CVE-2026-97015
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94513
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95922
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-95922
updates:
  - at: "2026-11-11T02:26:04Z"
    level: L2
    summary: added CVE-2026-109500,
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119995
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119996
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120000
  - at: "2026-11-11T05:56:44Z"
    level: L2
    summary: added CVE-2026-120000
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-80094
  - at: "2026-11-11T05:57:07Z"
    level: L2
    summary: added CVE-2026-118707
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84010
  - at: "2026-11-14T13:55:58Z"
    level: L1
    summary: 'merged coverage from Microsoft Windows Graphics Kernel: Heap-based buffer overflow (CVE-2026-95922)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-95922
---

CVE-2026-95922 is a heap-based buffer overflow vulnerability in the Windows Graphics Kernel. 

## Impact

This vulnerability allows an authorized attacker to elevate privileges locally.

## Recommendation

Consult the official Microsoft Security Update Guide for further information regarding this vulnerability.
