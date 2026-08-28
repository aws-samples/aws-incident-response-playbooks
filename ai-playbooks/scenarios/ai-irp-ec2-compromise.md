# AI IRP: EC2 Instance Compromise

An EC2 instance is under attacker control — running malicious processes, communicating with C2 infrastructure, or being used for lateral movement. The instance itself is evidence. **NEVER terminate it.**

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  NEVER TERMINATE A COMPROMISED EC2 INSTANCE.                ║
║  Termination destroys volatile memory, process state,       ║
║  and filesystem evidence. ISOLATE instead.                  ║
╚══════════════════════════════════════════════════════════════╝
```

The only exception is cryptomining at scale where cost is the primary concern. For that scenario, use `ai-irp-cryptomining.md` instead.

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Active C2 communication (GuardDuty Backdoor/Trojan finding) | P1 |
| Lateral movement to other instances | P1 |
| Cryptocurrency mining detected | P2 (route to cryptomining playbook) |
| Unusual outbound traffic, no confirmed C2 | P2 |
| Suspicious process but no network indicators | P3 |

## Step 1: Confirm and Identify

```bash
# Identify the instance and its context
aws ec2 describe-instances \
  --instance-ids i-COMPROMISED \
  --query "Reservations[].Instances[].{
    InstanceId:InstanceId,
    State:State.Name,
    VpcId:VpcId,
    SubnetId:SubnetId,
    SecurityGroups:SecurityGroups[].GroupId,
    IamProfile:IamInstanceProfile.Arn,
    LaunchTime:LaunchTime,
    PrivateIp:PrivateIpAddress,
    PublicIp:PublicIpAddress,
    Tags:Tags
  }" --output json

# Check if instance is in an Auto Scaling Group
aws autoscaling describe-auto-scaling-instances \
  --instance-ids i-COMPROMISED
```

**Decision: Is the instance in an ASG?**

| Situation | Action |
|-----------|--------|
| In ASG | Detach from ASG FIRST (Step 2), then isolate |
| Standalone | Proceed directly to isolation (Step 3) |
| Part of ECS/EKS cluster | Drain node first, then isolate |

## Step 2: Detach from Auto Scaling Group

> ⚠️ **Requires user confirmation before executing.**

If the instance is in an ASG, detach it to prevent the ASG from terminating it during scale-in.

```bash
# Detach instance from ASG (keeps it running, ASG launches replacement)
aws autoscaling detach-instances \
  --instance-ids i-COMPROMISED \
  --auto-scaling-group-name ASG_NAME \
  --should-decrement-desired-capacity

# Verify detachment
aws autoscaling describe-auto-scaling-instances \
  --instance-ids i-COMPROMISED
```

## Step 3: Isolate — Security Group Swap

> ⚠️ **Requires user confirmation before executing.**

Replace all security groups with a forensic isolation group that blocks all traffic. This immediately severs all network connectivity to and from the instance — the attacker loses C2, but legitimate services on this instance will also stop.

```bash
# Create isolation security group (if it doesn't exist)
aws ec2 create-security-group \
  --group-name forensic-isolation \
  --description "IR: No inbound or outbound traffic" \
  --vpc-id vpc-EXAMPLE

# The group has no rules = denies all inbound
# Add explicit deny-all outbound (SGs allow all outbound by default)
# Actually: Remove the default outbound rule
ISOLATION_SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=forensic-isolation" \
  --query "SecurityGroups[0].GroupId" --output text)

aws ec2 revoke-security-group-egress \
  --group-id $ISOLATION_SG_ID \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# SWAP security groups on the compromised instance
aws ec2 modify-instance-attribute \
  --instance-id i-COMPROMISED \
  --groups $ISOLATION_SG_ID
```

## Step 4: Preserve Evidence — EBS Snapshots

```bash
# Get all volumes attached to the instance
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids i-COMPROMISED \
  --query "Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId" \
  --output text)

# Snapshot each volume
for VOL in $VOLUMES; do
  aws ec2 create-snapshot \
    --volume-id $VOL \
    --description "IR-EVIDENCE: i-COMPROMISED $(date -u +%Y%m%dT%H%M%SZ)" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=IR-Case,Value=CASE_ID},{Key=Evidence,Value=true}]"
done
```

## Step 5: Preserve Evidence — Memory Capture (If Required)

Memory capture requires SSM agent access. Only possible if the instance had SSM configured before isolation.

```bash
# Check if SSM agent is reachable (may not work after SG swap)
aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=i-COMPROMISED"

# If SSM is available, capture memory using LiME or similar
# This requires pre-staged tooling on the instance
aws ssm send-command \
  --instance-ids i-COMPROMISED \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["insmod /tmp/lime.ko path=/tmp/memory.lime format=lime"]'
```

> **NOTE**: If SSM is not available after isolation, memory capture may require temporarily allowing outbound to SSM endpoints only. Discuss with IR lead before modifying isolation.

## Step 6: Investigate — What Did the Attacker Do?

```bash
# Check instance metadata credentials usage (were IMDS creds stolen?)
# Query CloudTrail for the instance role
```

**Key Athena query — all API calls from the instance's role:**

```sql
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       userAgent, errorCode, awsRegion
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%INSTANCE_ROLE_NAME%'
  AND sourceIPAddress != 'INSTANCE_PRIVATE_IP'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — check for lateral movement (RunInstances, SSM commands):**

```sql
SELECT eventTime, eventName, requestParameters, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%INSTANCE_ROLE_NAME%'
  AND eventName IN (
    'RunInstances', 'SendCommand', 'StartSession',
    'CreateNetworkInterface', 'AuthorizeSecurityGroupIngress'
  )
ORDER BY eventTime ASC;
```

**Key Athena query — VPC Flow Logs for C2 communication:**

```sql
SELECT srcaddr, dstaddr, dstport, protocol, packets, bytes,
       start, "end", action
FROM vpc_flow_logs
WHERE srcaddr = 'INSTANCE_PRIVATE_IP'
  AND action = 'ACCEPT'
  AND dstport NOT IN (443, 80, 53)
  AND start BETWEEN COMPROMISE_START AND COMPROMISE_END
ORDER BY bytes DESC
LIMIT 50;
```

## Step 7: Check for Lateral Movement

```bash
# Check if the instance role was used to launch other instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[?LaunchTime>='COMPROMISE_TIME'].{
    Id:InstanceId,IP:PrivateIpAddress,Launch:LaunchTime}" \
  --output table

# Check for SSM commands sent to other instances
aws ssm list-commands \
  --filters "Key=InvokedAfter,Value=COMPROMISE_TIME"

# Check for security group modifications (attacker opening access)
```

## Step 8: Eradicate

> ⚠️ **Requires user confirmation before executing.**

```bash
# Revoke instance role credentials (add session revocation policy)
aws iam put-role-policy \
  --role-name INSTANCE_ROLE \
  --policy-name RevokeCompromisedSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "CURRENT_UTC_TIMESTAMP"}
      }
    }]
  }'

# Remove any attacker-created resources found in Step 6-7
# Remove any modified security group rules
# Remove any unauthorized IAM policies
```

## Step 9: Recover

> ⚠️ **Requires user confirmation before executing.**

**Do NOT restore the compromised instance.** Launch a clean replacement from your organization's known-good AMI or Infrastructure as Code. The specific AMI and configuration depend on your environment — consult the application owner or IaC repository.

```bash
# Launch replacement from known-good AMI or via IaC
# Ensure IMDSv2 is enforced on the new instance
aws ec2 run-instances \
  --image-id ami-KNOWN_GOOD \
  --instance-type ORIGINAL_TYPE \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --security-group-ids sg-PRODUCTION \
  --subnet-id subnet-ORIGINAL \
  --iam-instance-profile Name=ORIGINAL_PROFILE

# Remove session revocation policy after new instance is running
aws iam delete-role-policy \
  --role-name INSTANCE_ROLE \
  --policy-name RevokeCompromisedSessions
```

## Step 10: Harden

- [ ] Enforce IMDSv2 on all instances (`HttpTokens: required`)
- [ ] Reduce instance role permissions to least privilege
- [ ] Enable VPC Flow Logs on all VPCs
- [ ] Deploy endpoint detection (GuardDuty Runtime Monitoring)
- [ ] Restrict outbound traffic via security groups or NAT gateway
- [ ] Enable SSM Session Manager (eliminates need for SSH/RDP)
- [ ] Implement network segmentation for sensitive workloads

## Escalation Triggers

- C2 traffic to known APT infrastructure → Engage threat intelligence team
- Lateral movement confirmed to multiple instances → Expand scope, consider full VPC isolation
- Instance role used to access other accounts → Cross-account incident, engage all account owners
- Evidence of data staging or exfiltration → Legal notification, possible P1 escalation
- Attacker modified CloudTrail or VPC Flow Logs → Assume broader compromise

## Reference

Full human playbook: `IRP-EC2Compromise.md`
