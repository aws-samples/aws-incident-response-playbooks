# AI IRP: Cryptomining

Unauthorized cryptocurrency mining using your AWS resources. Unlike other incidents, **cost is the primary concern** — miners can burn thousands of dollars per hour. This is the ONE scenario where immediate termination is appropriate.

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  TERMINATE FIRST, INVESTIGATE LATER.                        ║
║  Cryptomining costs $$$$ per hour. Every minute you         ║
║  investigate before terminating costs real money.           ║
║  Evidence is in CloudTrail, not on the instance.            ║
╚══════════════════════════════════════════════════════════════╝
```

Exception: If you suspect the mining is a cover for a deeper compromise (data exfiltration, lateral movement), treat as EC2 compromise instead and preserve evidence.

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Hundreds of instances launched across regions | P1 (cost emergency) |
| GuardDuty CryptoCurrency finding | P2 |
| Single instance mining, caught quickly | P3 |
| Cost anomaly alert, mining suspected | P2 |

## Step 1: Confirm Cryptomining

```bash
# Check GuardDuty for crypto findings
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": [
        "CryptoCurrency:EC2/BitcoinTool.B",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "CryptoCurrency:Runtime/BitcoinTool.B",
        "CryptoCurrency:Runtime/BitcoinTool.B!DNS"
      ]}
    }
  }' --region us-east-1
```

**Decision: Is this just mining or something deeper?**

| Indicator | Assessment |
|-----------|-----------|
| Only mining processes, no other suspicious activity | Pure cryptomining — TERMINATE |
| Mining + data access + lateral movement | Deeper compromise — route to `ai-irp-ec2-compromise.md` |
| Mining + new IAM users/roles created | Credential compromise + mining — contain credentials first |

## Step 2: Identify ALL Mining Instances (Multi-Region)

Attackers launch instances in ALL regions simultaneously. You must check every region.

```bash
# Check ALL regions for unauthorized instances
for REGION in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "=== $REGION ==="
  aws ec2 describe-instances \
    --region $REGION \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[].{
      Id:InstanceId,
      Type:InstanceType,
      Launch:LaunchTime,
      IP:PublicIpAddress
    }" --output table
done

# Look specifically for GPU/compute-optimized instances (mining favorites)
for REGION in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws ec2 describe-instances \
    --region $REGION \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[?starts_with(InstanceType,'p3') || starts_with(InstanceType,'p4') || starts_with(InstanceType,'g4') || starts_with(InstanceType,'g5') || starts_with(InstanceType,'c5') || starts_with(InstanceType,'c6')].{Id:InstanceId,Type:InstanceType,Region:'$REGION'}" \
    --output table
done
```

## Step 3: TERMINATE — Bulk Instance Termination

> ⚠️ **Requires user confirmation before executing. This action is IRREVERSIBLE.**
>
> Verify you are only terminating attacker-launched instances. Filter by launch time, instance type, or tags to avoid killing production. Present the specific instance IDs and let the responder confirm each batch.

```bash
# Terminate all unauthorized instances in a region
aws ec2 terminate-instances \
  --instance-ids i-MINING1 i-MINING2 i-MINING3 \
  --region REGION

# For large numbers, use a loop per region
for REGION in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  INSTANCES=$(aws ec2 describe-instances \
    --region $REGION \
    --filters "Name=instance-state-name,Values=running" \
    --filters "Name=launch-time,Values=COMPROMISE_TIME*" \
    --query "Reservations[].Instances[].InstanceId" --output text)
  
  if [ -n "$INSTANCES" ]; then
    echo "Terminating in $REGION: $INSTANCES"
    aws ec2 terminate-instances --instance-ids $INSTANCES --region $REGION
  fi
done
```


## Step 4: Contain the Credential

> ⚠️ **Requires user confirmation before executing.**

The attacker got in somehow. Find and disable that access.

```bash
# What credential launched the mining instances?
```

**Key Athena query — who launched the instances:**

```sql
SELECT eventTime, userIdentity.arn, userIdentity.accessKeyId,
       sourceIPAddress, requestParameters.instanceType,
       responseElements.instancesSet.items[0].instanceId,
       awsRegion
FROM cloudtrail_logs
WHERE eventName = 'RunInstances'
  AND eventTime > 'COMPROMISE_START'
ORDER BY eventTime ASC;
```

```bash
# Disable the compromised credential immediately
aws iam update-access-key \
  --access-key-id AKIAEXAMPLE \
  --status Inactive \
  --user-name COMPROMISED_USER

# Or if it's a role, revoke sessions
aws iam put-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-name RevokeOldSessions \
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
```

## Step 5: Check for Persistence

Miners often create persistence to re-launch if terminated.

```bash
# Check for Lambda functions that re-launch instances
aws lambda list-functions --region us-east-1 \
  --query "Functions[?LastModified>='COMPROMISE_TIME']"

# Check for EC2 launch templates created by attacker
aws ec2 describe-launch-templates \
  --query "LaunchTemplates[?CreateTime>='COMPROMISE_TIME']"

# Check for Auto Scaling Groups (will re-launch terminated instances!)
aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?CreatedTime>='COMPROMISE_TIME']"

# Check for EventBridge rules that trigger instance launches
aws events list-rules --region us-east-1

# Check for Step Functions or ECS tasks
aws ecs list-tasks --region us-east-1 --desired-status RUNNING
```

**Key Athena query — find ALL resources created by attacker:**

```sql
SELECT eventTime, eventName, eventSource, awsRegion,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'ATTACKER_KEY_ID'
  AND eventName LIKE 'Create%'
ORDER BY eventTime ASC;
```

## Step 6: Remove Persistence

> ⚠️ **Requires user confirmation before executing.**

```bash
# Delete attacker ASGs (these WILL relaunch instances)
aws autoscaling delete-auto-scaling-group \
  --auto-scaling-group-name ATTACKER_ASG \
  --force-delete

# Delete attacker Lambda functions
aws lambda delete-function --function-name ATTACKER_FUNCTION

# Delete attacker launch templates
aws ec2 delete-launch-template --launch-template-id lt-ATTACKER

# Delete attacker EventBridge rules
aws events remove-targets --rule ATTACKER_RULE --ids "1"
aws events delete-rule --name ATTACKER_RULE

# Delete attacker IAM users/roles (full credential compromise cleanup)
# See ai-irp-credential-compromise.md Step 6
```

## Step 7: Apply Emergency Service Control Policy

> ⚠️ **Requires user confirmation before executing.**

Prevent further instance launches while you clean up. This blocks ALL `RunInstances` calls in the affected account except from the IR break-glass role.

```bash
# Apply SCP to block RunInstances (if using AWS Organizations)
# Apply to the compromised account's OU
aws organizations attach-policy \
  --policy-id p-EMERGENCY_DENY_EC2 \
  --target-id ou-COMPROMISED_OU

# Emergency SCP content:
# {
#   "Version": "2012-10-17",
#   "Statement": [{
#     "Effect": "Deny",
#     "Action": ["ec2:RunInstances"],
#     "Resource": "*",
#     "Condition": {
#       "StringNotEquals": {
#         "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/IRBreakGlass"
#       }
#     }
#   }]
# }
```

## Step 8: Cost Mitigation

```bash
# Check current month's cost impact
aws ce get-cost-and-usage \
  --time-period Start=MONTH_START,End=TODAY \
  --granularity DAILY \
  --metrics "UnblendedCost" \
  --filter '{
    "Dimensions": {
      "Key": "SERVICE",
      "Values": ["Amazon Elastic Compute Cloud - Compute"]
    }
  }'
```

- Open AWS Support case requesting cost adjustment for unauthorized usage
- Include CloudTrail evidence showing unauthorized RunInstances calls
- AWS may credit costs for confirmed unauthorized activity

## Step 9: Harden

- [ ] Set EC2 instance limits (Service Quotas) to match actual needs
- [ ] Enable AWS Budgets with alerts for cost anomalies
- [ ] Restrict `ec2:RunInstances` to specific instance types via IAM/SCP
- [ ] Restrict regions via SCP (deny all unused regions)
- [ ] Enable GuardDuty in all regions
- [ ] Implement preventive SCPs blocking GPU/compute instance types if not needed
- [ ] Set up Cost Anomaly Detection alerts

## Escalation Triggers

- Cost exceeds $10,000 → Immediate AWS Support case for cost relief
- Instances in regions you can't access → AWS Support needed
- Attacker has persistence you can't remove → Escalate to full account compromise
- Mining is cover for data exfiltration → Pivot to EC2 compromise playbook

## Reference

Full human playbook: `IRP-Cryptomining.md`
