---
inclusion: manual
description: |
  Incident response playbook for ransomware incidents affecting AWS resources.
  - Invoke with "steering-irp-credential-compromise.md" when responding to compromised credentials.
  - Invoke with "steering-irp-data-access.md" when responding to unintended access to Amazon S3 buckets.
  - Invoke with "steering-irp-ransomware.md" when responding to ransomware incidents.
  - Invoke with "steering-irp-api-security-breach.md" when responding to API security incidents.
---

# Playbook: Ransomware

## Incident Type
Ransomware — when malicious code encrypts data or locks access to AWS resources (EC2 instances, S3 objects, EBS volumes) and a threat actor demands payment for restoration. Variants include crypto ransomware (encrypts files/objects), locker ransomware (locks device access), and hybrid types.

## Quick Reference

| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | Identify affected resources, ransomware strain, attack vector, timeline | Affected resource IDs, ransomware type, compromise timestamp documented |
| Contain | Isolate infected resources, revoke compromised credentials, block spread vectors | No new infections for 30+ min, network isolation confirmed |
| Eradicate | Remove malware, eliminate persistence mechanisms, patch attack vector | No malicious artifacts remain, vulnerability mitigated |
| Recover | Restore from clean backups/snapshots, rebuild if necessary | Data integrity confirmed, applications functioning normally |
| Post-Incident | Document lessons learned, harden defenses | Report filed, playbook updated, preventive controls deployed |

---

## Part 1: Acquire, Preserve, Document Evidence

### 1.1 Identify the Alert Source

Common sources for ransomware alerts:
- **EC2 instance unreachable** (SSH/RDP fails despite correct network config, no AWS service issues)
- **Monitoring alarms** (CloudWatch metrics anomalies, application health checks failing)
- **GuardDuty findings** (e.g., malware-related or unauthorized access findings)
- **Security Hub alerts**
- **Ransom demand** received via email, on-screen message, or alternate channel
- **Suspicious S3 bucket with threatening name** (e.g., `we-stole-ur-data-*`, `your-files-encrypted-*`) discovered during routine account review
- **Ransom note object found in S3** (e.g., `README_DECRYPT.txt`, `warning.txt`, `all_your_data_are_belong_to_us.txt`)
- **Billing anomalies** (unexpected cost spikes from attacker resource usage)
- **Amazon Inspector findings** (known CVE exploitation)
- **External notification** (security researcher, law enforcement, anonymous tip)

### 1.2 Determine Ransomware Type

Identify the variant to guide response strategy:
- **Crypto ransomware** — files/objects are encrypted (check S3 object properties for unexpected encryption keys, EBS volume encryption changes)
- **Locker ransomware** — device access is blocked (instance unreachable but running)
- **Extortion ransomware (delete + extort)** — data is exfiltrated then deleted (not encrypted), with threat to publish or sell unless ransom is paid. No encryption occurs; the leverage is data exposure. Look for: bulk `GetObject` followed by bulk `DeleteObject` in CloudTrail, a newly created bucket containing a ransom note, and `warning.txt`/`README` objects placed in victim buckets.
- **Unknown/hybrid** — treat as crypto ransomware until confirmed otherwise

**Check S3 object encryption (if S3 objects are inaccessible):**
```bash
# Check encryption properties on affected objects
aws s3api head-object --bucket <bucket-name> --key <object-key>

# List recent PutObject or CopyObject events that may have re-encrypted objects
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
  --start-time <start-timestamp> \
  --max-results 50
```

**Check EBS volume encryption changes:**
```bash
# Describe volumes attached to the affected instance
aws ec2 describe-volumes \
  --filters Name=attachment.instance-id,Values=<instance-id> \
  --query 'Volumes[].[VolumeId,Encrypted,KmsKeyId,State]' \
  --output table
```

### 1.3 Identify Affected Resources and Scope

```bash
# Describe the affected EC2 instance
aws ec2 describe-instances --instance-ids <instance-id>

# Check instance status and reachability
aws ec2 describe-instance-status --instance-ids <instance-id>

# Use Amazon Detective to investigate activity (if enabled)
# Navigate to Detective console → Search → enter instance ID or IAM principal
```

Determine scope:
- [ ] How many instances/resources are affected?
- [ ] Is the infection spreading to other resources?
- [ ] What is the data classification level of affected resources?
- [ ] Are there related abuse notifications from AWS?

### 1.4 Establish Timeline

```bash
# Search CloudTrail for suspicious activity around the affected resources
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<instance-id> \
  --start-time <estimated-compromise-time> \
  --max-results 50

# Check CloudWatch metrics for anomalous behavior
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name NetworkIn \
  --dimensions Name=InstanceId,Value=<instance-id> \
  --start-time <start-timestamp> \
  --end-time <end-timestamp> \
  --period 300 \
  --statistics Average
```

Document:
- **First anomaly:** When did metrics/logs first show unusual behavior?
- **Likely infection time:** When was the ransomware likely deployed? (may precede detection)
- **Detection time:** When was the incident identified?
- **Response start:** When did you begin responding?

### 1.5 Check for Credential Compromise as Attack Vector

```bash
# Search CloudTrail for unauthorized IAM activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time <estimated-compromise-time> \
  --max-results 20

# Check for new access keys created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time <estimated-compromise-time> \
  --max-results 20
```

If credential compromise is confirmed, also invoke the credential compromise playbook (`steering-irp-credential-compromise.md`).

### 1.6 Document and Communicate

- [ ] Create/update incident ticket with: affected resource IDs, ransomware type, timeline, data classification
- [ ] Identify stakeholders from CMDB or application risk register
- [ ] Open incident response bridge
- [ ] Notify: Security team, application owners, legal counsel
- [ ] If regulated data is involved, notify compliance team
- [ ] Inform law enforcement contacts if required by jurisdiction
- [ ] Preserve evidence chain of custody documentation

---

## Part 2: Contain the Incident

**Goal:** Isolate infected resources to prevent spread and block attacker access.

### 2.1 Network Isolation of Affected Instances

```bash
# Create a quarantine security group with no inbound/outbound rules
aws ec2 create-security-group \
  --group-name ransomware-quarantine \
  --description "Quarantine SG for ransomware incident" \
  --vpc-id <vpc-id>

# Replace all security groups on the affected instance with the quarantine SG
aws ec2 modify-instance-attribute \
  --instance-id <instance-id> \
  --groups <quarantine-sg-id>
```

⚠️ **Warning:** This immediately cuts all network access to the instance, including legitimate traffic. Coordinate with application owners.

**Note on connection tracking:** Existing established connections may persist after security group changes. For immediate full isolation, consider also modifying the subnet's network ACL:

```bash
# Add deny-all rules to the subnet NACL (affects all instances in the subnet)
aws ec2 create-network-acl-entry \
  --network-acl-id <nacl-id> \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block 0.0.0.0/0 \
  --ingress

aws ec2 create-network-acl-entry \
  --network-acl-id <nacl-id> \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block 0.0.0.0/0 \
  --egress
```

⚠️ **Warning:** NACL changes affect all instances in the subnet. Only use if the entire subnet is compromised or the instance is in an isolated subnet.

### 2.2 Contain S3-Based Ransomware

This section covers two S3 ransomware patterns: **crypto** (objects re-encrypted) and **extortion** (objects exfiltrated then deleted, ransom note left in a new attacker-created bucket).

**Step 1 — Identify and investigate any suspicious new buckets:**

```bash
# List all buckets with creation timestamps — attacker-created buckets will postdate normal resources
aws s3api list-buckets --query 'Buckets[].[Name,CreationDate]' --output table

# List contents of any suspicious bucket (ransom notes, exfiltrated data)
aws s3 ls s3://<suspicious-bucket> --recursive

# Read any ransom note objects
aws s3 cp s3://<suspicious-bucket>/<ransom-note-key> -
```

**Step 2 — Check all victim buckets for planted ransom notes:**

```bash
# Look for unexpected objects in buckets that should not contain them
# Common ransom note filenames: warning.txt, README_DECRYPT.txt, !!!HOW_TO_DECRYPT!!!.txt
aws s3 ls s3://<bucket-name> | grep -iE 'warning|readme|decrypt|ransom|locked|restore'
```

**Step 3 — Assess data recoverability via versioning:**

```bash
# Check versioning status — if Suspended or not enabled, deleted objects are NOT recoverable
aws s3api get-bucket-versioning --bucket <bucket-name>

# If versioning is Enabled, check for delete markers on deleted objects
aws s3api list-object-versions --bucket <bucket-name> \
  --query 'DeleteMarkers[].[Key,LastModified,VersionId]' --output table

# If versioning is Enabled, restore a deleted object by removing its delete marker
aws s3api delete-object --bucket <bucket-name> --key <object-key> \
  --version-id <delete-marker-version-id>
```

⚠️ **If versioning was NOT enabled on the bucket when the deletion occurred, the objects are permanently gone.** Document this for the impact assessment and regulatory notification decisions.

**Step 4 — Restrict the attacker-created ransom bucket:**

```bash
# Prevent further writes to the attacker's bucket while preserving it as evidence
aws s3api put-bucket-policy --bucket <attacker-bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::<attacker-bucket-name>",
      "arn:aws:s3:::<attacker-bucket-name>/*"
    ],
    "Condition": {
      "StringNotEquals": {"aws:PrincipalAccount": "<your-account-id>"}
    }
  }]
}'
```

**Step 5 — Lock down victim buckets to stop further access:**

```bash
# Enable Block Public Access on all affected buckets
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Apply restrictive bucket policy to deny all external principals
aws s3api put-bucket-policy --bucket <bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::<bucket-name>",
      "arn:aws:s3:::<bucket-name>/*"
    ],
    "Condition": {
      "StringNotEquals": {"aws:PrincipalAccount": "<your-account-id>"}
    }
  }]
}'
```

### 2.3 Revoke Compromised Credentials

If credentials were used as the attack vector:

```bash
# Disable IAM user access keys
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <access-key-id> \
  --status Inactive

# Revoke temporary role sessions
aws iam put-role-policy \
  --role-name <role-name> \
  --policy-name AWSRevokeOlderSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "<current-iso-timestamp>"}
      }
    }]
  }'
```

### 2.4 Check for Unauthorized IAM Activity and Revoke

```bash
# Check for unauthorized IAM users, policies, roles, or temporary credentials
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time <compromise-timestamp> \
  --max-results 20

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time <compromise-timestamp> \
  --max-results 20

# MCP batch opportunity: the above lookups can be run in parallel
```

Delete any unauthorized IAM users, roles, policies, and revoke temporary credentials found.

### 2.5 Consider Account-Level Containment (Drastic)

If the infection is widespread and the account is part of AWS Organizations:

```bash
# Apply a deny-all SCP to the affected account (NOT the management account)
aws organizations create-policy \
  --name "RansomwareQuarantine" \
  --description "Emergency quarantine for ransomware incident" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

aws organizations attach-policy \
  --policy-id <policy-id> \
  --target-id <account-id>
```

⚠️ **Warning:** This blocks ALL API calls in the account, affecting all workloads. Use only as a last resort for severe, spreading infections. Cannot be applied to the management account.

### 2.6 Patch the Attack Vector

If the ransomware exploited unpatched software:
- For mutable architectures: apply patches in place using AWS Systems Manager
- For immutable architectures: update the AMI and redeploy

```bash
# Check for missing patches via Systems Manager
aws ssm describe-instance-patch-states --instance-ids <instance-id>

# Run patch baseline
aws ssm send-command \
  --instance-ids <instance-id> \
  --document-name "AWS-RunPatchBaseline" \
  --parameters '{"Operation":["Install"]}'
```

### 2.7 Verify Containment

Monitor for 30+ minutes to confirm no new infections or attacker activity:

```bash
# Monitor CloudTrail for continued activity from compromised credentials
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<access-key-id> \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 10

# Check for new GuardDuty findings
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"updatedAt":{"GreaterThanOrEqual":'"$(date -u -v-30M +%s000)"'}}}'
```

If new infections or activity appear, containment has failed — reassess the attack vector and expand isolation.

---

## Part 3: Eradicate the Incident

**Goal:** Remove all malicious artifacts, eliminate persistence mechanisms, and close the attack vector.

### 3.1 Identify the Ransomware Strain

- Review ransom notes, encrypted file extensions, or on-screen messages
- Cross-reference with known ransomware databases (e.g., ID Ransomware, No More Ransom)
- Check if third-party decryption tools are available for the identified strain

### 3.2 Forensic Analysis in Isolated Environment

⚠️ **Warning:** Do not run anti-malware on the live infected instance — this may alert the attacker or trigger data destruction.

```bash
# Create a snapshot of the infected instance's volumes for forensic analysis
aws ec2 create-snapshot \
  --volume-id <volume-id> \
  --description "Forensic snapshot - ransomware incident <ticket-id>"

# Create an AMI of the infected instance for preservation
aws ec2 create-image \
  --instance-id <instance-id> \
  --name "forensic-image-<ticket-id>" \
  --description "Forensic image - ransomware incident" \
  --no-reboot
```

Analyze the forensic copy in an isolated environment:
- Run anti-malware/anti-virus scans
- Identify indicators of compromise (IOCs)
- Determine the initial infection vector
- Identify any lateral movement or persistence mechanisms

### 3.3 Review GuardDuty Findings

```bash
# List recent high/medium severity findings
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"severity":{"GreaterThanOrEqual":4}}}'

# Get finding details
aws guardduty get-findings --detector-id <detector-id> --finding-ids <finding-id>
```

GuardDuty findings provide remediation recommendations — follow them for each relevant finding.

### 3.4 Remove Malicious Artifacts

Based on forensic analysis:
- [ ] Remove any malware identified on infected instances
- [ ] Delete unauthorized IAM users, roles, policies, and access keys
- [ ] Terminate any attacker-created resources (EC2 instances, Lambda functions, etc.)
- [ ] Remove any persistence mechanisms (scheduled tasks, cron jobs, startup scripts)
- [ ] Revoke any modified trust policies or permission escalations

```bash
# List all IAM users (look for unfamiliar ones)
aws iam list-users

# List all roles (look for unfamiliar ones)
aws iam list-roles

# Check for recently launched instances (potential attacker infrastructure)
aws ec2 describe-instances \
  --filters Name=launch-time,Values=<compromise-date>* \
  --query 'Reservations[].Instances[].[InstanceId,LaunchTime,InstanceType,Tags]' \
  --output table

# MCP batch opportunity: the above checks can be run in parallel
```

### 3.5 Close the Attack Vector

Based on root cause analysis:
- [ ] Patch exploited vulnerabilities on all potentially affected instances
- [ ] Update AMIs used in Auto Scaling launch configurations/templates
- [ ] Verify patches against the Mitre CVE database
- [ ] Block identified malicious IPs/domains in security groups or WAF rules
- [ ] Enforce IMDSv2 if SSRF was part of the attack chain

If eradication reveals a different attack vector (e.g., credential compromise, S3 data exfiltration), loop back to Part 1 and invoke the corresponding additional playbook.

```bash
# Enforce IMDSv2 on instances
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-endpoint enabled
```

---

## Part 4: Recover from the Incident

**Goal:** Restore data and services from clean backups, or rebuild from known-good configurations.

### 4.1 Identify Restore Points

```bash
# List available EBS snapshots
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=volume-id,Values=<volume-id> \
  --query 'Snapshots[].[SnapshotId,StartTime,Description]' \
  --output table

# List available AMIs
aws ec2 describe-images --owners self \
  --query 'Images[].[ImageId,CreationDate,Name]' \
  --output table

# List RDS snapshots (if applicable)
aws rds describe-db-snapshots \
  --query 'DBSnapshots[].[DBSnapshotIdentifier,SnapshotCreateTime,Status]' \
  --output table

# Check S3 versioning for object recovery
aws s3api list-object-versions --bucket <bucket-name> --prefix <key-prefix>

# MCP batch opportunity: the above checks can be run in parallel
```

Choose a restore point that predates the infection time established in Part 1.

### 4.2 Restore from Backups

**For EC2 instances (from snapshot):**
```bash
# Create a new volume from a clean snapshot
aws ec2 create-volume \
  --snapshot-id <clean-snapshot-id> \
  --availability-zone <az> \
  --volume-type gp3

# Terminate the infected instance (or keep quarantined for forensics)
# Launch a new instance with the restored volume
```

**For S3 objects (from versioning):**
```bash
# Restore a previous version by copying it over the current version
aws s3api copy-object \
  --bucket <bucket-name> \
  --key <object-key> \
  --copy-source <bucket-name>/<object-key>?versionId=<pre-infection-version-id>

# Remove delete markers if objects were deleted
aws s3api delete-object --bucket <bucket-name> --key <object-key> \
  --version-id <delete-marker-version-id>
```

**For Auto Scaling groups:**
```bash
# Update launch template with clean AMI
aws ec2 create-launch-template-version \
  --launch-template-id <template-id> \
  --source-version <current-version> \
  --launch-template-data '{"ImageId":"<clean-ami-id>"}'

# Trigger instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name <asg-name>
```

**If no backup exists and decryption tools are available:**
- Use identified third-party decryption tools in an isolated environment
- Validate decrypted data integrity before restoring to production
- Remove decrypted data from the infected instance, rebuild the instance, then restore

### 4.3 Rebuild if Necessary

If backups are unavailable and decryption is not possible:
- Rebuild from CMDB configuration documentation
- Redeploy from infrastructure-as-code (CloudFormation, CDK, Terraform)
- Restore application data from any available secondary sources (cross-region replicas, Glacier, on-premises backups)

### 4.4 Verify Recovery

- [ ] Restored data integrity confirmed (checksums, application-level validation)
- [ ] Affected applications functioning normally
- [ ] Monitoring dashboards show normal metrics
- [ ] No evidence of reinfection in CloudTrail or GuardDuty
- [ ] CMDB updated with any resource changes

If suspicious activity reoccurs, return to Part 1 and reassess.

---

## Part 5: Post-Incident Activity

### 5.1 Document Lessons Learned

Create post-incident report covering:
- **Timeline:** When did each phase occur?
- **Root cause:** How did the ransomware gain entry? (unpatched vulnerability, phishing, credential compromise, misconfiguration)
- **Ransomware strain:** What variant was used? Was decryption possible?
- **Impact:** What resources were affected? What data was lost or encrypted? Data classification?
- **Response effectiveness:** What worked? What didn't? How long did each phase take?
- **Recommendations:** Process, tooling, and architecture improvements

### 5.2 Retrospective Questions

- What detection would have alerted to the ransomware sooner?
- Were backups adequate for recovery? Were they tested?
- What patching or configuration gap allowed the initial infection?
- Could network segmentation have limited the blast radius?
- What automation would have accelerated containment?

### 5.3 Update Defenses

Based on findings:
- [ ] Ensure all instances are patched and using current AMIs
- [ ] Enable/verify AWS Backup with appropriate retention policies
- [ ] Enable S3 Versioning and consider Object Lock for critical data
- [ ] Enforce IMDSv2 across all EC2 instances
- [ ] Review and tighten IAM policies (least privilege)
- [ ] Enable/enhance GuardDuty, Security Hub, and Amazon Inspector
- [ ] Implement network segmentation to limit lateral movement
- [ ] Deploy endpoint protection on EC2 instances
- [ ] Consider SCPs or permission boundaries for additional guardrails
- [ ] Propose updates to this playbook and related steering files based on lessons learned — present changes to the operator for review and approval before modifying any steering files

### 5.4 Regulatory Notifications

If required by your jurisdiction:
- [ ] Notify relevant authorities within required timeframe
- [ ] Report to law enforcement agencies if applicable
- [ ] Document notification for compliance records
- [ ] Consider voluntary reporting to ransomware tracking databases or government agencies

---

## References

- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [NIST SP 800-61 R3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Amazon S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS Backup Documentation](https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html)
- [Amazon GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [Amazon Inspector Documentation](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html)
- [IMDSv2 for SSRF Mitigation](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html)
- [Querying CloudTrail Logs with Athena](https://aws.amazon.com/premiumsupport/knowledge-center/athena-tables-search-cloudtrail-logs/)
- [No More Ransom Project](https://www.nomoreransom.org/)
