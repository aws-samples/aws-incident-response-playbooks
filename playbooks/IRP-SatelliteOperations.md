# IRP-SatelliteOperations: Satellite Ground Segment and Space Operations

| Field | Value |
| --- | --- |
| **Playbook Version** | 1.0 |
| **Last Reviewed** | 2026-06-25 |
| **Status** | Draft |
| **NIST Framework** | SP 800-61r3 (CSF 2.0 Community Profile) |
| **Related Playbooks** | IRP-CredCompromise |

> **Disclaimer**: This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

This playbook addresses incident response for satellite operations running on AWS, covering both the ground segment (mission control, ground stations, data processing pipelines) and the operational interfaces to space assets. Satellite operations present unique IR challenges: limited contact windows (typically 8 minutes per 90-minute orbit for LEO spacecraft), bandwidth-constrained command uplinks, irreversible consequences of certain space commands, and the difficulty of distinguishing cyber incidents from environmental anomalies such as single-event upsets (SEUs) caused by radiation. This playbook provides a structured approach to detecting, containing, eradicating, and recovering from security incidents across the full satellite operations stack on AWS, aligned with NIST SP 800-61r3 and sector-specific requirements including Space Policy Directive 5 (SPD-5) and NIS2.

---

## Applicable Finding Types

The detection signals that should route a responder to this playbook:

| Source | Finding / Event Type | Severity |
| --- | --- | --- |
| Amazon GuardDuty | Unusual Ground Station API calls (such as `ReserveContact` from unexpected source) | HIGH |
| Amazon GuardDuty | Compromised IAM credentials with Ground Station permissions | HIGH |
| Amazon GuardDuty | `DeleteDataflowEndpointGroup` outside maintenance windows | HIGH |
| AWS CloudTrail / CloudTrail Insights | Unusual Ground Station API call patterns | MEDIUM |
| Amazon CloudWatch | Anomaly detection alarm: telemetry outside expected thresholds with no environmental correlation | MEDIUM |
| Custom / Application | Unexpected command acknowledgments (commands your system did not send) | CRITICAL |
| Custom / Application | Telemetry values deviating from predicted orbital mechanics or thermal models | MEDIUM |
| Custom / Application | Unscheduled satellite mode transitions | HIGH |
| Custom / Application | Communication link anomalies outside known environmental factors | MEDIUM |
| Custom / Application | Power consumption patterns inconsistent with operational state | MEDIUM |

> **Note**: Amazon GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

---

## Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria |
| --- | --- |
| **P1 (Critical)** | Unauthorized command uploaded to spacecraft; confirmed unauthorized access to Ground Station command path; active data exfiltration from ground segment; ground segment ransomware with upcoming pass window |
| **P2 (High)** | Suspicious API activity against Ground Station resources; unauthorized contact reservation or cancellation; credential compromise with Ground Station permissions; anomalous behavior on command processing EC2 instances |
| **P3 (Medium)** | Telemetry anomaly that cannot be immediately attributed to environmental factors; unauthorized access to telemetry archives without evidence of command path compromise |
| **P4 (Low)** | Policy violations on satellite operations IAM roles without active threat indicators; informational findings on development or simulation environments |

---

## Part 1: Prepare

**CSF 2.0 Functions**: Govern, Identify, Protect

**Goal**: Ensure the right configurations, access, and processes are in place before this incident type occurs.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all applicable accounts and regions before an incident occurs.

- [ ] **AWS CloudTrail** enabled with multi-region trail, management and data events logging to Amazon S3 with integrity validation enabled
- [ ] **Amazon S3 Object Lock** (Compliance mode) configured on the CloudTrail log bucket, preventing any principal (including root) from modifying or deleting log files until retention expires
- [ ] **Amazon GuardDuty** enabled with findings exported to AWS Security Hub
- [ ] **Amazon Detective** enabled for graph-based investigation of entity relationships
- [ ] **Amazon VPC Flow Logs** enabled for all VPCs hosting ground segment workloads (data processing EC2 instances)
- [ ] **Amazon Data Firehose** configured to stream VPC Flow Logs to Amazon OpenSearch Service for near-real-time network-level log correlation
- [ ] **Amazon Timestream for InfluxDB** configured for telemetry time-series storage and baseline comparison
- [ ] **Amazon CloudWatch** anomaly detection configured on custom telemetry metrics published by ground segment applications
- [ ] **Amazon EventBridge** rules configured to route GuardDuty findings and CloudWatch alarms to AWS Step Functions for orchestrated response workflows
- [ ] **AWS Step Functions** state machine deployed with human approval gates (via Amazon SNS) for high-consequence decisions
- [ ] **AWS Ground Station** CloudTrail data event logging enabled

> **Automation opportunity**: Use AWS Config conformance packs or AWS Security Hub standards to continuously validate these prerequisites.

### 1.2 IAM and Access Prerequisites

Ensure the following access is pre-provisioned and tested. Do not provision break-glass access during an active incident.

- [ ] Break-glass IAM role with least-privilege IR permissions exists, documented, and tested quarterly
- [ ] IR team members can assume the break-glass role with MFA
- [ ] Access to AWS Security Incident Response console (if subscribed) is confirmed
- [ ] Forensic account (isolated, no connectivity to production ground segment) is available for evidence preservation
- [ ] Service control policies (SCPs) prevent deletion of CloudTrail trails and S3 Object Lock configurations

### 1.3 Communication and Escalation

> Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
| --- | --- |
| IR Lead | Overall incident coordination, status updates, pass window scheduling decisions |
| Mission Director | Authorization for spacecraft command decisions, safe-mode determinations |
| Account Owner | Business context, authorization for ground segment containment actions |
| Spacecraft Operations Engineer | Technical assessment of space asset state, environmental vs. cyber discrimination |
| Legal / Compliance | Regulatory notification obligations (NIS2, SPD-5), evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2) |

**Escalation path**: Detection triggered > IR Lead notified > Severity assessed using discrimination decision tree (Section 2.1) > P1/P2: Mission Director consulted, AWS CIRT engaged, Legal notified > P3/P4: IR Lead manages internally

**Contact window constraint**: For LEO operations, the escalation path must complete within the orbital period minus contact window duration (approximately 82 minutes). Pre-position all decision authorities before the next pass.

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: semi-annually for P1 scenarios, annually for P3/P4.

**Suggested tabletop scenarios** (see Part 5 Appendix for full scenario details):

1. Unauthorized command upload via compromised operator credential
2. Ground segment ransomware with upcoming satellite pass in 45 minutes
3. Subtle telemetry manipulation that avoids standard threshold alarms

**Reference**: [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)

---

## Part 2: Detect and Analyze

**CSF 2.0 Functions**: Detect, Respond (Analyze)

**Goal**: Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Discrimination Decision Tree

Satellite operations require a specialized triage process because anomalies can originate from the space environment rather than from cyber threats. Apply this four-step decision tree before escalating.

**Step 1: Does the anomaly correlate with a known environmental condition?**

Check solar activity indices (Kp, Dst), South Atlantic Anomaly transit timing, eclipse transitions, or known RF interference zones. If yes, the anomaly is likely environmental.

**Step 2: Does the anomaly correlate with a Ground Station API call or configuration change?**

Check CloudTrail. If yes, investigate the identity and authorization of that call.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=groundstation.amazonaws.com \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,Name:EventName,User:Username}' \
  --output table

```

**Step 3: Is the anomaly consistent with known adversary tactics, techniques, and procedures (TTPs) for satellite systems?**

Cross-reference with threat intelligence (Space ISAC advisories, CISA alerts).

**Step 4: Is the anomaly localized or constellation-wide?**

A single-satellite anomaly is more likely hardware or environmental. Simultaneous anomalies across multiple satellites suggest a ground-side or systemic issue.

Use Amazon Detective to visualize entity relationships during investigation. Detective correlates CloudTrail logs, VPC Flow Logs, and GuardDuty findings into an entity-relationship graph, surfacing which IAM roles accessed Ground Station APIs and what other resources those roles touched.

### 2.2 Evidence Collection

Collect and preserve the following before taking any containment actions. Evidence collected after containment may be incomplete or altered.

> **Warning**: Do not terminate instances or delete resources before snapshotting and preserving evidence. Do not send any commands to the spacecraft until command path integrity is verified.

**CloudTrail: Filter for contact scheduling events**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ReserveContact \
  --start-time 2026-06-01T00:00:00Z \
  --end-time 2026-06-11T23:59:59Z \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, event: (.CloudTrailEvent | fromjson | {ip: .sourceIPAddress, agent: .userAgent, identity: .userIdentity.arn, params: .requestParameters})}'

```

This extracts four fields critical to an investigation: `sourceIPAddress` (expected operations center or unfamiliar location), `userAgent` (mission planning software or unfamiliar SDK client), `userIdentity.arn` (authorized operator or compromised credential), and `requestParameters` (which satellite, ground station, and time window were requested).

**Ground Station contacts in the incident window**

```bash
aws groundstation list-contacts \
  --status-list COMPLETED FAILED \
  --start-time 2026-06-01T00:00:00Z \
  --end-time 2026-06-11T23:59:59Z \
  --output table

```

**Detailed contact information for suspicious contacts**

```bash
aws groundstation describe-contact \
  --contact-id <contact-uuid> \
  --output json

```

Compare the output against your expected contact schedule to identify unauthorized or unexpected activity.

**Additional evidence to collect:**

| Evidence Type | Source | Where to Store |
| --- | --- | --- |
| CloudTrail logs (incident time window) | S3 bucket (integrity-validated) / Amazon Athena | Forensic S3 bucket with Object Lock |
| GuardDuty finding JSON | GuardDuty console export | Forensic S3 bucket |
| VPC Flow Logs (ground segment VPCs) | Amazon OpenSearch Service | Forensic S3 bucket |
| EC2 instance memory/disk snapshots | EBS snapshots to forensic account | Forensic account |
| Ground Station contact records | `describe-contact` for each contact | IR ticket and forensic bucket |
| Telemetry data (anomaly window) | Amazon Timestream for InfluxDB | Forensic S3 bucket with Object Lock |
| IAM credential reports | `aws iam get-credential-report` | IR ticket |

### 2.3 Space-Side Indicators of Compromise

On the satellite side, watch for:

- Unexpected command acknowledgments (commands your system did not send)
- Telemetry values deviating from predicted orbital mechanics or thermal models
- Unscheduled satellite mode transitions
- Communication link anomalies outside known environmental factors
- Power consumption patterns inconsistent with the satellite's operational state

These indicators are most meaningful when compared against telemetry baselines stored in Amazon Timestream for InfluxDB.

### 2.4 Getting Help from AWS

For P1 or P2 incidents:

- **AWS Security Incident Response service** (if subscribed): Open a case via the Security Incident Response console. The service provides integrated case management with 24/7 access to the AWS Customer Incident Response Team.
- **AWS Support**: Open a support case with severity "Critical" or "Urgent."
- All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

---

## Part 3: Contain

**CSF 2.0 Function**: Respond (Contain)

**Goal**: Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Domains

Containment splits into two domains with fundamentally different timelines.

**Ground segment containment (immediate)**:

- Attach an explicit deny-all IAM policy to compromised identities, preserving the entity for forensics rather than deleting it
- Modify security groups on satellite data processing instances to restrict all traffic except to the forensic analysis environment
- Isolate the affected VPC by removing routes to other VPCs and the internet while preserving logging connectivity
- Modify AWS Ground Station dataflow endpoint configurations to route data to a clean backup environment so that subsequent contacts deliver data to uncompromised infrastructure

**Space segment containment (next available pass)**:

- Switch to backup command encryption keys if primary command authentication is suspected compromised
- Command the satellite to a predefined safe mode that limits operations to authenticated commands from a restricted set of ground stations
- If the constellation uses inter-satellite links, isolate the affected satellite from the mesh to prevent potential lateral movement
- Route subsequent contacts through geographically diverse ground stations to reduce single-point-of-compromise risk

### 3.2 Containment Decision Framework

Every containment decision involves a trade-off between security and operational continuity. Pre-approve decision criteria before an incident occurs:

| Scenario | Action | Acceptable if |
| --- | --- | --- |
| Suspected unauthorized command upload | Skip next contact, rotate command keys | Loss of one contact window is tolerable for the mission |
| Ground credential compromise, space segment unaffected | Isolate ground, maintain contacts via backup | Backup infrastructure is pre-provisioned |
| Active data exfiltration from ground segment | Cut network connectivity | Data sensitivity outweighs one orbit of missed data |
| Telemetry manipulation suspected | Cross-validate via multiple ground stations | Multiple stations are available for comparison |

### 3.3 Automated Containment

Use pre-built automated runbooks to reduce response time from hours to minutes. The automation flow: detection sources feed findings into Amazon EventBridge, which triggers an AWS Step Functions orchestration workflow. The workflow executes immediate automated containment actions (such as IAM policy changes and instance snapshots) while routing high-impact decisions (such as satellite safe-mode commands) through a human approval gate via Amazon SNS before execution.

---

## Part 4: Eradicate and Recover

**CSF 2.0 Function**: Respond (Eradicate), Recover

**Goal**: Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Ground Segment Eradication and Recovery

- **Rebuild** affected Amazon EC2 instances from known-good AMIs stored in a separate, access-restricted account
- **Rotate** all credentials: IAM users, roles, access keys, and application-layer secrets used for satellite communication
- **Redeploy** infrastructure from version-controlled AWS CloudFormation templates, verifying source integrity through Git commit signatures
- **Verify data integrity** by comparing checksums of recently processed satellite data against expected values before resuming normal operations

### 4.2 Space Segment Validation

- If spacecraft firmware was potentially compromised, follow your validated firmware reload procedure
- Test scheduling and configuration using the **AWS Ground Station digital twin**, which validates mission profiles, contact scheduling, and integration with your mission control software without consuming production antenna capacity or requiring spectrum licensing. The digital twin does not support data delivery or telemetry delivery, so it validates your operational workflow rather than simulating actual satellite communication.
- Require **dual approval** for the first post-incident command sequence
- Monitor satellite health telemetry for at least **three full orbit periods** (approximately 4.5 hours for a typical LEO spacecraft) after recovery to confirm nominal behavior

### 4.3 Detection Hardening

After recovery, configure CloudWatch anomaly detection on additional telemetry metrics based on patterns observed during the incident:

```bash
aws cloudwatch put-anomaly-detector \
  --namespace "SatelliteOps/Telemetry" \
  --metric-name "SignalToNoiseRatio" \
  --stat "Average" \
  --dimensions Name=SatelliteId,Value=SAT-001 \
  --configuration '{
    "ExcludedTimeRanges": [],
    "MetricTimezone": "UTC"
  }'

```

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "SAT-001-SNR-Anomaly" \
  --evaluation-periods 3 \
  --comparison-operator LessThanLowerOrGreaterThanUpperThreshold \
  --threshold-metric-id ad1 \
  --metrics '[
    {"Id": "m1", "MetricStat": {"Metric": {"Namespace": "SatelliteOps/Telemetry", "MetricName": "SignalToNoiseRatio", "Dimensions": [{"Name": "SatelliteId", "Value": "SAT-001"}]}, "Period": 300, "Stat": "Average"}},
    {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)"}
  ]' \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:satellite-security-alerts \
  --alarm-description "Triggers when SNR deviates from learned baseline by more than 2 standard deviations"

```

The `ANOMALY_DETECTION_BAND(m1, 2)` expression uses a band width of 2 standard deviations from the learned baseline. The model takes approximately two weeks of data to train and accounts for hourly, daily, and weekly seasonality patterns.

**Cleaning up** (if created for testing only):

```bash
aws cloudwatch delete-anomaly-detector \
  --single-metric-anomaly-detector \
    Namespace="SatelliteOps/Telemetry",MetricName="SignalToNoiseRatio",Stat="Average",Dimensions=[{Name=SatelliteId,Value=SAT-001}]

aws cloudwatch delete-alarms \
  --alarm-names "SAT-001-SNR-Anomaly"

```

---

## Part 5: Post-Incident Activity

**CSF 2.0 Function**: Identify (Improve)

**Goal**: Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Evidence Preservation

Satellite cyber incidents may involve national security implications, regulatory reporting obligations, or insurance claims. Preserving evidence with chain-of-custody rigor is critical.

- Store all log data in Amazon S3 with **Object Lock in compliance mode**, which prevents any principal (including the root account) from modifying or deleting data until the retention period expires
- Query archived logs in S3 using **Amazon Athena** for SQL-based investigation
- For near-real-time log analysis, configure your AWS CloudTrail trail to also deliver events to a CloudWatch Log Group, then query them with **Amazon CloudWatch Logs Insights**
- Document the complete timeline including: satellite orbital position at time of incident, ground station used, and space weather conditions during the event window

### 5.2 Regulatory Reporting

| Regulation | Reporting Requirement |
| --- | --- |
| **NIS2** (EU) | Early warning: 24 hours; Initial assessment: 72 hours; Final report: 1 month |
| **SPD-5** (US) | Share threat information with relevant government and industry bodies |
| **EU Space Act** | Still in legislative draft as of June 2026; may introduce additional obligations |

Engage legal counsel early, particularly if the incident may involve state-sponsored actors or affect services across multiple jurisdictions.

> **Warning**: Under NIS2, the clock starts at awareness, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

### 5.3 Runbooks

The following three runbooks address the most common satellite IR scenarios. Each specifies a trigger and the resulting actions.

**Runbook 1: Suspicious Ground Station API activity**

*Trigger*: Amazon GuardDuty or CloudTrail Insights detect unusual Ground Station API calls (such as `ReserveContact` from an unexpected source or `DeleteDataflowEndpointGroup` outside maintenance windows).

*Automated actions*:

1. Capture IAM entity details and session context
2. Snapshot all Amazon EC2 instances in the affected Ground Station VPC
3. Apply deny-all security group (preserve existing group for forensics)
4. Notify satellite operations and security teams via Amazon SNS
5. Create a case in AWS Security Incident Response
6. Log all actions to the forensic Amazon S3 bucket

**Runbook 2: Telemetry anomaly escalation**

*Trigger*: Amazon CloudWatch alarm detecting telemetry outside expected thresholds, with no known environmental correlation.

*Automated actions*:

1. Begin high-fidelity telemetry recording for subsequent contacts
2. Query the time-series data store (Amazon Timestream for InfluxDB) for historical baseline comparison
3. Cross-reference with space weather data (automated query to NOAA Space Weather Prediction Center)
4. If anomaly persists across multiple contacts without environmental correlation, escalate to security investigation
5. Pre-stage containment commands for human-in-the-loop approval

**Runbook 3: Ground segment credential compromise**

*Trigger*: Amazon GuardDuty finding indicating compromised IAM credentials with Ground Station permissions.

*Automated actions*:

1. Attach deny-all policy to the compromised identity
2. Identify all Ground Station contacts scheduled by that identity in the past 72 hours
3. Review contact outcomes to determine if commands were sent or data was routed to unexpected destinations
4. If commands were sent during suspicious contacts, flag for satellite health assessment at next pass
5. Provision clean replacement environment from AWS CloudFormation templates

**Orchestration**: Use AWS Step Functions to orchestrate multi-step response workflows that incorporate human decision points. A workflow can detect an anomaly, automatically gather context, present a decision to the on-call engineer ("Approve safe-mode command for Satellite-7?"), then execute the approved action during the next contact window.

### 5.4 Tabletop Exercise Scenarios

Regularly exercise your playbook with these scenarios designed to stress-test satellite-specific IR capabilities:

**Scenario 1: Unauthorized command upload**

An attacker compromises an operator credential and schedules a Ground Station contact to upload malicious firmware. Your detection fires when the `ReserveContact` call originates from an unrecognized IP address. Can your team cancel the contact before execution begins? What validation do you perform on the satellite afterward?

**Scenario 2: Ground segment ransomware**

Ransomware encrypts the Amazon EC2 instances running your mission operations center. Your next satellite pass is in 45 minutes, and the satellite requires a routine orbit maintenance maneuver within 3 hours. Can you bring up backup command generation capability in time? Do you have pre-generated emergency command sequences stored separately?

**Scenario 3: Telemetry manipulation**

An adversary with access to your data processing pipeline subtly modifies telemetry values to hide that they have altered the satellite's attitude. The modification avoids standard threshold alarms but gradually points the antenna away from its intended coverage area. Can you compare raw telemetry (from DigIF recordings) against processed telemetry to identify discrepancies?

Use the AWS Ground Station digital twin to validate that your scheduling and configuration runbooks execute correctly and that Amazon EventBridge events trigger the expected workflows, without risking production antenna capacity.

### 5.5 Implementation Roadmap

**Week 1**: Turn on AWS CloudTrail for all accounts with Ground Station resources. Activate Amazon GuardDuty in those accounts. Configure an Amazon S3 bucket with Object Lock for forensic log storage.

**Month 1**: Deploy VPC Flow Logs on satellite data processing VPCs. Establish telemetry baselines in a time-series data store (Amazon Timestream for InfluxDB or Amazon OpenSearch Service). Create the first automated runbook (suspicious API activity). Configure AWS Security Incident Response for satellite operations accounts.

**Quarter 1**: Build all three automated runbooks with AWS Step Functions orchestration. Conduct your first tabletop exercise. Integrate space weather data feeds. Test scheduling and Amazon EventBridge-triggered workflows using the Ground Station digital twin.

**Ongoing**: Exercise quarterly. Update runbooks as services evolve and your constellation changes. Participate in the Space Information Sharing and Analysis Center (Space ISAC) for awareness of evolving threat actor tactics targeting space systems.

---

## Appendix: Reference Links

- [NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS Ground Station User Guide](https://docs.aws.amazon.com/ground-station/latest/ug/what-is-aws-ground-station.html)
- [Test and integrate ground segment with AWS Ground Station digital twin](https://docs.aws.amazon.com/ground-station/latest/ug/digital-twin.html)
- [Amazon CloudWatch Anomaly Detection](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html)
- [Space Policy Directive 5 (SPD-5)](https://trumpwhitehouse.archives.gov/presidential-actions/memorandum-space-policy-directive-5-cybersecurity-principles-space-systems/)
- [NIST IR 8401: Satellite Ground Segment Cybersecurity Framework](https://csrc.nist.gov/pubs/ir/8401/final)
- [An Incident Response Playbook for Satellite Operations on AWS, Part 1: Detection and Forensic Readiness](https://aws.amazon.com/blogs/publicsector/an-incident-response-playbook-for-satellite-operations-on-aws-part-1-detection-and-forensic-readiness/)
- [An Incident Response Playbook for Satellite Operations on AWS, Part 2: Automated Response and Recovery](https://aws.amazon.com/blogs/publicsector/an-incident-response-playbook-for-satellite-operations-on-aws-part-2-automated-response-and-recovery/)

---

## Revision History

| Version | Date | Author | Change Summary |
| --- | --- | --- | --- |
| 1.0 | 2026-06-25 | Harshvardhan Chunawala | Initial draft |

