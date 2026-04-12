---
description: Incident response playbook for AWS API Gateway security breaches. Use this skill when responding to unauthorized API access, leaked or exposed API keys, API authentication bypass, missing or misconfigured API authorizers, abnormal API invocation volume or scraping, injection attacks via API endpoints, broken object-level authorization (BOLA/IDOR), data exfiltration through API Gateway, WAF bypass, AWS WAF alerts, CloudWatch alarms on API errors or invocation spikes, Security Hub findings on API Gateway misconfigurations, customer reports of API abuse, or billing spikes from unexpected API Gateway or Lambda invocations.
---

# Playbook: API Gateway Security Breach

## Incident Type
API Gateway Security Breach — When an AWS API Gateway endpoint (REST, HTTP, or WebSocket) has been attacked, abused, or misconfigured in a way that exposes backend systems or data to unauthorized actors. This includes leaked API keys, authentication bypass due to missing or misconfigured authorizers (IAM, Lambda, Cognito), abnormal request volume indicating scraping or abuse, injection attacks passed through the API to backend Lambda functions or data stores, broken object-level authorization allowing cross-tenant data access, and large-scale data exfiltration through the API layer. The application team owns the API Gateway infrastructure; the security team leads the response with application team support. Business impact includes sensitive data breach, service disruption for legitimate users, and downstream system compromise if the attacker pivots from the API to backend services.

## Quick Reference

| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | Identify affected API + stage, check authorizer config, query access/WAF logs, establish timeline | API ID, attacker IP(s), attack type, and timeline documented |
| Contain | Throttle stage + block attacker IP(s) via WAF rate-based rule and IP set | No new attack traffic for 15+ min, CloudWatch metrics return to baseline |
| Eradicate | Remove unauthorized API keys/IAM entities, restore API definition and authorizer config | API definition matches source control, all methods have correct authorizer |
| Recover | Re-enable stage, issue new API keys to legitimate clients, restore backend data | Legitimate clients confirmed working, metrics at baseline, no new CloudTrail events |
| Post-Incident | Document lessons learned, update defenses, notify stakeholders | Report filed, WAF rules hardened, playbook updated |

---

## Part 1: Acquire, Preserve, Document Evidence

### 1.1 Identify the Alert Source

Common sources for API Gateway security breach alerts:

**Primary Signals (often the first indicator):**
- **AWS WAF** — rate limit rule exceeded, AWS managed rule group match (SQLi, XSS, known bad IPs), geo-block triggered, or custom rule fired
- **CloudWatch alarm** — spike in `4XXError` or `5XXError` metric on an API Gateway stage
- **CloudWatch alarm** — abnormal `Count` (total invocation volume) on an API Gateway stage
- **Customer/user report** — "API returning unexpected data", "seeing other users' records", or "our API is being hammered"
- **Billing alert** — unexpected spike in API Gateway invocation costs or Lambda invocation/duration costs driven by abnormal request volume

**Secondary Signals (corroborating or configuration-based):**
- **Security Hub** — `APIGateway.1` (access logging not enabled on stage)
- **Security Hub** — `APIGateway.2` (stage not using TLS 1.2 minimum)
- **Security Hub** — `APIGateway.9` (execution logging not enabled)
- **CloudTrail** — management-plane changes to API Gateway: new deployments, authorizer modifications, WAF web ACL disassociated, stage settings changed
- **GuardDuty** — credential-based finding (e.g., `UnauthorizedAccess:IAMUser/*`) where the affected principal has permissions to manage API Gateway resources

---

### 1.2 Identify the Affected API and Stage

```bash
# List all API Gateway REST APIs
aws apigateway get-rest-apis \
  --query 'items[*].[id,name,createdDate]' \
  --output table

# List all stages for a specific API
aws apigateway get-stages \
  --rest-api-id <api-id> \
  --query 'item[*].[stageName,createdDate,lastUpdatedDate,webAclArn]' \
  --output table

# Get full stage detail (logging, throttling, WAF, variables)
aws apigateway get-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name>
```
# MCP batch opportunity: run get-stages across all API IDs in parallel

Document:
- [ ] API ID and name
- [ ] Stage name and last modified timestamp
- [ ] WAF web ACL ARN (if associated)
- [ ] Whether access logging is enabled (`accessLogSettings.destinationArn`)
- [ ] Whether execution logging is enabled (`methodSettings.*.loggingLevel`)

---

### 1.3 Check Authorizer Configuration

```bash
# List authorizers on the API
aws apigateway get-authorizers \
  --rest-api-id <api-id> \
  --query 'items[*].[id,name,type,authorizerUri,identitySource]' \
  --output table

# Check resource policy (if using resource-based auth)
aws apigateway get-rest-api \
  --rest-api-id <api-id> \
  --query 'policy'

# List API keys in use
aws apigateway get-api-keys \
  --include-values \
  --query 'items[*].[id,name,enabled,createdDate,lastUpdatedDate]' \
  --output table
```

Document:
- [ ] Authorizer type (IAM / Cognito / Lambda / None)
- [ ] Whether API key requirement is enforced on methods
- [ ] Whether any authorizers were recently modified

---

### 1.4 Analyze API Gateway Access Logs

Access logs are delivered to a CloudWatch Logs group configured on the stage.

```bash
# Find the access log group for the stage
aws apigateway get-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --query 'accessLogSettings.destinationArn'

# Query access logs for high error rates (last 1 hour)
aws logs start-query \
  --log-group-name <access-log-group> \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string '
    fields @timestamp, ip, httpMethod, resourcePath, status, responseLength
    | filter status >= 400
    | stats count(*) as errorCount by ip, resourcePath, status
    | sort errorCount desc
    | limit 50'

# Wait for query to complete, then retrieve results
aws logs get-query-results --query-id <query-id>

# Query for top source IPs by request volume
aws logs start-query \
  --log-group-name <access-log-group> \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string '
    fields @timestamp, ip, httpMethod, resourcePath
    | stats count(*) as requestCount by ip
    | sort requestCount desc
    | limit 20'

# Query for requests missing authorization
aws logs start-query \
  --log-group-name <access-log-group> \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string '
    fields @timestamp, ip, httpMethod, resourcePath, status, caller
    | filter status == 403 or caller == "-"
    | sort @timestamp desc
    | limit 50'
```
# MCP batch opportunity: run multiple Logs Insights queries in parallel

---

### 1.5 Analyze WAF Logs

WAF logs capture full request details including matched rules.

```bash
# Find WAF log group or S3 bucket
aws wafv2 get-logging-configuration \
  --resource-arn <api-gateway-stage-arn>

# If WAF logs go to CloudWatch Logs — query for blocked requests
aws logs start-query \
  --log-group-name <waf-log-group> \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string '
    fields @timestamp, httpRequest.clientIp, httpRequest.uri,
           httpRequest.httpMethod, action, terminatingRuleId
    | filter action = "BLOCK"
    | stats count(*) as blockCount by httpRequest.clientIp, terminatingRuleId
    | sort blockCount desc
    | limit 20'

# List WAF rules on the associated web ACL
aws wafv2 get-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --query 'WebACL.Rules[*].[Name,Priority,Action]' \
  --output table
```

---

### 1.6 Investigate CloudTrail for Management-Plane Changes

```bash
# Search for API Gateway configuration changes in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::ApiGateway::RestApi \
  --start-time <compromise-timestamp> \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50

# Search for specific high-risk events
for event in CreateDeployment UpdateStage DeleteStage CreateAuthorizer \
             UpdateAuthorizer DeleteAuthorizer CreateApiKey DeleteApiKey; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$event \
    --start-time <compromise-timestamp> \
    --max-results 10
done
```
# MCP batch opportunity: look up all event types in parallel

Document:
- [ ] Any recent deployments pushed to the affected stage
- [ ] Any authorizer changes
- [ ] Any WAF disassociation events
- [ ] IAM principal that made any changes

---

### 1.7 Establish Timeline and Scope

Document the following before proceeding to containment:

| Item | Value |
|------|-------|
| First suspicious request timestamp | |
| Alert trigger timestamp | |
| Last API Gateway config change | |
| Attacker source IP(s) | |
| Targeted endpoint(s) / resource path(s) | |
| Total suspicious request volume | |
| Backend Lambda functions invoked | |
| Sensitive data potentially returned | |
| Attack type(s) identified | |

---

### 1.8 Document and Communicate

- [ ] Create/update incident ticket with: API ID, stage, attacker IP(s), timeline, attack type
- [ ] Identify API/application owners from CMDB or API Gateway tags
- [ ] Open war room bridge
- [ ] Notify: Security team, Application team, Legal (if PII/sensitive data involved)
- [ ] Preserve log evidence: export access logs, WAF logs, CloudTrail events to S3

---

## Part 2: Contain the Incident

**Goal:** Throttle all traffic to the API until the attack vector is identified and closed.

### 2.1 Preserve Log Evidence Before Any Changes

Before making any configuration changes, export current log evidence:

```bash
# Export CloudWatch access logs to S3 for preservation
aws logs create-export-task \
  --log-group-name <access-log-group> \
  --from $(date -u -v-24H +%s000) \
  --to $(date -u +%s000) \
  --destination <evidence-s3-bucket> \
  --destination-prefix "incident-<ticket-id>/access-logs/"

# Export WAF logs if in CloudWatch Logs
aws logs create-export-task \
  --log-group-name <waf-log-group> \
  --from $(date -u -v-24H +%s000) \
  --to $(date -u +%s000) \
  --destination <evidence-s3-bucket> \
  --destination-prefix "incident-<ticket-id>/waf-logs/"
```

---

### 2.2 Enable WAF Logging (if not already enabled)

```bash
# Associate WAF logging to CloudWatch Logs
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "<api-gateway-stage-arn>",
    "LogDestinationConfigs": ["arn:aws:logs:<region>:<account-id>:log-group:aws-waf-logs-<name>"],
    "RedactedFields": []
  }'
```

---

### 2.3 Associate WAF with API Gateway Stage (if not already associated)

```bash
# Create a new web ACL (if none exists)
aws wafv2 create-web-acl \
  --name "emergency-api-protection" \
  --scope REGIONAL \
  --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=emergency-api-protection \
  --rules '[]'

# Associate web ACL with API Gateway stage
aws wafv2 associate-web-acl \
  --web-acl-arn <web-acl-arn> \
  --resource-arn arn:aws:apigateway:<region>::/restapis/<api-id>/stages/<stage-name>
```

⚠️ **Warning:** Associating a new WAF web ACL with a default `Allow` action will not immediately block traffic — add rules in the following steps. Confirm the association before proceeding.

---

### 2.4 Block Attacker IP(s) via WAF IP Set

```bash
# Create an IP set with attacker IPs
aws wafv2 create-ip-set \
  --name "blocked-attacker-ips" \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "<attacker-ip-1>/32" "<attacker-ip-2>/32"

# Add a block rule to the web ACL using the IP set
aws wafv2 update-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action Allow={} \
  --rules '[{
    "Name": "BlockAttackerIPs",
    "Priority": 0,
    "Statement": {
      "IPSetReferenceStatement": {
        "ARN": "<ip-set-arn>"
      }
    },
    "Action": {"Block": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "BlockAttackerIPs"
    }
  }]' \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=<web-acl-name>
```

⚠️ **Warning:** Blocking by IP may affect legitimate users sharing a NAT gateway, corporate proxy, or CDN exit node. Verify the IP is not a shared egress point before blocking. If uncertain, use rate-based rules instead (Step 2.5).

---

### 2.5 Add WAF Rate-Based Rule

```bash
# Add a rate-based rule to throttle any single IP exceeding threshold
aws wafv2 update-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action Allow={} \
  --rules '[{
    "Name": "RateLimitRule",
    "Priority": 1,
    "Statement": {
      "RateBasedStatement": {
        "Limit": 500,
        "AggregateKeyType": "IP"
      }
    },
    "Action": {"Block": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitRule"
    }
  }]'
```

⚠️ **Warning:** The rate limit applies to ALL IPs, not just the attacker. Set the threshold above your expected legitimate peak request rate per IP to avoid blocking real users. Coordinate with the application team to confirm a safe threshold.

---

### 2.6 Reduce Stage-Level Throttling

```bash
# Document current values before changing
aws apigateway get-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --query '[defaultRouteSettings.throttlingBurstLimit,defaultRouteSettings.throttlingRateLimit]'

# Reduce burst and rate limits on the stage
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --patch-operations \
    op=replace,path=/defaultRouteSettings/throttlingBurstLimit,value=100 \
    op=replace,path=/defaultRouteSettings/throttlingRateLimit,value=50
```

⚠️ **Warning:** Stage-level throttling applies to all callers including legitimate users. Coordinate with the application team before reducing limits in production. Document the original values so they can be restored in Part 4.

---

### 2.7 Disable Compromised API Key (if API key auth is the attack vector)

```bash
# List API keys to find the compromised one
aws apigateway get-api-keys \
  --include-values \
  --query 'items[?name==`<key-name>`].[id,name,enabled]'

# Disable the API key
aws apigateway update-api-key \
  --api-key <api-key-id> \
  --patch-operations op=replace,path=/enabled,value=false
```

⚠️ **Warning:** Disabling an API key immediately breaks all integrations using that key. Confirm with the application team which services or clients use this key before disabling.

---

### 2.8 Deploy Usage Plan with Hard Quotas (if rate-based rules are insufficient)

```bash
# Create a restrictive usage plan
aws apigateway create-usage-plan \
  --name "emergency-throttle" \
  --api-stages apiId=<api-id>,stage=<stage-name> \
  --throttle burstLimit=50,rateLimit=25 \
  --quota limit=1000,period=DAY
```

⚠️ **Warning:** Usage plan quotas apply to API keys associated with the plan. If legitimate high-volume clients are associated, they will be throttled. Confirm scope with the application team.

---

### 2.9 Take Stage Offline — Last Resort

Only use this if all other containment options have failed and the attack is causing active data breach or service degradation.

```bash
# Set stage throttling to zero (effectively takes API offline)
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --patch-operations \
    op=replace,path=/defaultRouteSettings/throttlingBurstLimit,value=0 \
    op=replace,path=/defaultRouteSettings/throttlingRateLimit,value=0
```

⚠️ **Warning:** Setting throttling to 0 causes a complete service outage for ALL users of this API stage. This is a last resort. Obtain explicit approval from the application team and incident commander before executing. Document the exact time this action was taken.

---

### 2.10 Revoke IAM Credentials (if IAM auth is the attack vector)

If the API is using IAM authorization and an IAM principal's credentials were used to make unauthorized API calls, follow `skill-irp-credential-compromise` in parallel for credential revocation steps.

---

### 2.11 Verify Containment

Monitor for 15+ minutes after containment actions:

```bash
# Check WAF blocked request metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=<web-acl-name> Name=Region,Value=<region> Name=Rule,Value=BlockAttackerIPs \
  --start-time $(date -u -v-15M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum

# Check API Gateway 4XX error rate returning to baseline
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name 4XXError \
  --dimensions Name=ApiName,Value=<api-name> Name=Stage,Value=<stage-name> \
  --start-time $(date -u -v-15M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum

# Check Lambda invocation count returning to baseline
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=<function-name> \
  --start-time $(date -u -v-15M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum
```
# MCP batch opportunity: run all CloudWatch metric queries in parallel

**Containment is verified when ALL of the following are true:**
- [ ] WAF blocked request count for attacker IP(s) has stabilized (no new requests getting through)
- [ ] CloudWatch `4XXError` and `Count` metrics have returned to baseline
- [ ] Access logs show no new requests from attacker source IP(s) for 15+ minutes
- [ ] WAF logs confirm rate-based rule is actively blocking
- [ ] Lambda invocation count has returned to expected baseline
- [ ] No new suspicious CloudTrail management-plane events in the last 15 minutes

If new attack traffic appears from different IPs, the attacker may be rotating IPs — consider enabling AWS WAF Bot Control or Fraud Control managed rule groups.

---

## Part 3: Eradicate the Incident

**Goal:** Remove all attacker-created resources, close the exploited vulnerability, and harden the API configuration to prevent recurrence.

### 3.1 Audit and Remove Unauthorized API Keys

```bash
# List all API keys — look for keys created after the compromise timestamp
aws apigateway get-api-keys \
  --include-values \
  --query 'items[*].[id,name,enabled,createdDate,lastUpdatedDate]' \
  --output table

# For each suspicious API key, check which usage plans it is associated with
aws apigateway get-usage-plan-keys \
  --usage-plan-id <usage-plan-id> \
  --query 'items[*].[id,name,type]' \
  --output table

# Delete unauthorized API key
aws apigateway delete-api-key \
  --api-key <api-key-id>
```

After removing unauthorized keys, rotate all remaining legitimate API keys:

```bash
# Step 1: Create replacement key
aws apigateway create-api-key \
  --name "<original-key-name>-rotated" \
  --enabled \
  --stage-keys restApiId=<api-id>,stageName=<stage-name>

# Step 2: Associate new key with usage plan
aws apigateway create-usage-plan-key \
  --usage-plan-id <usage-plan-id> \
  --key-id <new-key-id> \
  --key-type API_KEY

# Step 3: Coordinate with application team to update clients
# Step 4: Disable and delete old key after clients are updated
aws apigateway update-api-key \
  --api-key <old-key-id> \
  --patch-operations op=replace,path=/enabled,value=false

aws apigateway delete-api-key \
  --api-key <old-key-id>
```

⚠️ **Warning:** Deleting old API keys before clients are updated will break legitimate integrations. Coordinate the cutover with the application team.

---

### 3.2 Audit and Remove Unauthorized IAM Entities

```bash
# List IAM users created after the compromise timestamp
aws iam list-users \
  --query 'Users[?CreateDate>=`<compromise-timestamp>`].[UserName,CreateDate,UserId]' \
  --output table

# List IAM roles created after the compromise timestamp
aws iam list-roles \
  --query 'Roles[?CreateDate>=`<compromise-timestamp>`].[RoleName,CreateDate,RoleId]' \
  --output table

# For each suspicious IAM entity, check attached policies
aws iam list-attached-user-policies --user-name <suspicious-user>
aws iam list-user-policies --user-name <suspicious-user>
aws iam list-attached-role-policies --role-name <suspicious-role>
aws iam list-role-policies --role-name <suspicious-role>
```
# MCP batch opportunity: check policies for all suspicious entities in parallel

```bash
# Remove unauthorized IAM user (after removing dependencies)
aws iam delete-access-key --user-name <user> --access-key-id <key-id>
aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>
aws iam delete-user-policy --user-name <user> --policy-name <policy-name>
aws iam delete-user --user-name <user>

# Remove unauthorized IAM role (after removing dependencies)
aws iam detach-role-policy --role-name <role> --policy-arn <policy-arn>
aws iam delete-role-policy --role-name <role> --policy-name <policy-name>
aws iam delete-role --role-name <role>
```

---

### 3.3 Inspect and Restore API Definition

Check whether the API definition was tampered with via `ImportRestApi` or `PutRestApi`:

```bash
# Export the current API definition
aws apigateway get-export \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --export-type oas30 \
  --accepts application/json \
  --parameters extensions=apigateway \
  output.json

# List all deployments — compare timestamps against known-good deployments
aws apigateway get-deployments \
  --rest-api-id <api-id> \
  --query 'items[*].[id,description,createdDate]' \
  --output table

# Roll back to a known-good deployment
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --patch-operations op=replace,path=/deploymentId,value=<known-good-deployment-id>
```

Compare the exported API definition against your source control (e.g., OpenAPI spec in Git) to identify any unauthorized endpoints, integration changes, or auth bypasses introduced by the attacker.

---

### 3.4 Inspect and Restore Authorizer Configuration

```bash
# List all authorizers
aws apigateway get-authorizers \
  --rest-api-id <api-id> \
  --query 'items[*].[id,name,type,authorizerUri,identitySource,authorizerResultTtlInSeconds]' \
  --output table

# Check each method to confirm authorizer is enforced
aws apigateway get-resources \
  --rest-api-id <api-id> \
  --query 'items[*].[id,path,resourceMethods]' \
  --output table

# For a specific resource and method, get method detail
aws apigateway get-method \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method <GET|POST|ANY> \
  --query '[authorizationType,authorizerId,apiKeyRequired]'
```

If the authorizer was tampered with or methods were set to `NONE` auth:

```bash
# Restore authorizer on a specific method
aws apigateway update-method \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method <GET|POST|ANY> \
  --patch-operations \
    op=replace,path=/authorizationType,value=CUSTOM \
    op=replace,path=/authorizerId,value=<authorizer-id>

# Re-deploy after restoring auth configuration
aws apigateway create-deployment \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --description "Post-incident auth restoration"
```

⚠️ **Warning:** Changing authorizer configuration and re-deploying affects all callers of the API. Test in a non-production stage first where possible, and coordinate with the application team before deploying to production.

---

### 3.5 Check for Lambda Authorizer Backdoor

If the API uses a Lambda authorizer, inspect the function code for tampering:

```bash
# Get the Lambda authorizer function name from the authorizer config
aws apigateway get-authorizer \
  --rest-api-id <api-id> \
  --authorizer-id <authorizer-id> \
  --query 'authorizerUri'

# List Lambda function versions — look for versions published after compromise
aws lambda list-versions-by-function \
  --function-name <authorizer-function-name> \
  --query 'Versions[*].[Version,LastModified,Description]' \
  --output table

# Download current function code for review
aws lambda get-function \
  --function-name <authorizer-function-name> \
  --query 'Code.Location'
# Download the zip from the returned pre-signed URL and inspect
```

If the Lambda authorizer code was modified to always return `Allow`, redeploy from your source control pipeline immediately.

---

### 3.6 Tighten IAM Policies for API Gateway Principals

Review IAM policies for all principals with `apigateway:*` permissions and enforce least privilege:

```bash
# Find all IAM entities with API Gateway permissions
aws iam get-account-authorization-details \
  --filter User Role \
  --query 'UserDetailList[?AttachedManagedPolicies[?contains(PolicyName, `APIGateway`)]].UserName' \
  --output text
```

Replace broad `apigateway:*` grants with specific actions required per principal. Coordinate IAM policy updates with the application and security teams.

---

### 3.7 Iterate Until Clean

After completing Steps 3.1–3.6:

- [ ] Re-run CloudTrail lookup for API Gateway management events — no new unauthorized changes
- [ ] Re-run access log queries — no new requests from attacker IP(s) or patterns
- [ ] Confirm all IAM entities created by attacker have been removed
- [ ] Confirm API definition matches known-good version in source control
- [ ] Confirm all methods have correct authorizer configuration
- [ ] Confirm Lambda authorizer code matches known-good version in source control

---

## Part 4: Recover from the Incident

**Goal:** Restore the API to full production operation with verified secure configuration and confirmed legitimate traffic only.

### 4.1 Remove Emergency WAF IP Block Rules

Once the attack has fully stopped (verified in Part 2), remove temporary IP block rules to avoid permanently blocking IPs that may be reused by legitimate users:

```bash
# Get current web ACL lock token
aws wafv2 get-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --query '[WebACL.Rules, LockToken]'

# Update web ACL to remove the emergency BlockAttackerIPs rule
# (retain the rate-based rule as a permanent hardening measure)
aws wafv2 update-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action Allow={} \
  --rules '[<remaining-rules-without-BlockAttackerIPs>]' \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=<web-acl-name>

# Delete the IP set if no longer needed
aws wafv2 delete-ip-set \
  --name blocked-attacker-ips \
  --scope REGIONAL \
  --id <ip-set-id> \
  --lock-token <ip-set-lock-token>
```

⚠️ **Warning:** Only remove IP block rules after confirming the attack has fully stopped and the attack vector has been closed in Part 3. Removing blocks prematurely may allow the attacker to resume.

---

### 4.2 Re-enable API Stage if Taken Offline

If the stage was taken offline during containment (throttling set to 0), restore to pre-incident throttling values:

```bash
# Restore stage throttling to pre-incident values
# (use values documented during containment Step 2.6)
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage-name> \
  --patch-operations \
    op=replace,path=/defaultRouteSettings/throttlingBurstLimit,value=<original-burst-limit> \
    op=replace,path=/defaultRouteSettings/throttlingRateLimit,value=<original-rate-limit>
```

⚠️ **Warning:** Restore throttling values to pre-incident levels only after the attack vector is confirmed closed. Coordinate with the application team to confirm the original values before restoring.

---

### 4.3 Issue New API Keys to Legitimate Clients

After rotating API keys in Part 3, coordinate with the application team to distribute new keys to all legitimate clients:

```bash
# Confirm new API key is active and associated with usage plan
aws apigateway get-api-key \
  --api-key <new-key-id> \
  --include-value \
  --query '[id,name,enabled,stageKeys]'

# Confirm usage plan association
aws apigateway get-usage-plan-keys \
  --usage-plan-id <usage-plan-id> \
  --query 'items[*].[id,name,type]' \
  --output table
```

- [ ] Notify all legitimate API clients of new key values via secure channel
- [ ] Confirm each client has updated their configuration and is successfully authenticating
- [ ] Confirm old compromised keys are disabled and deleted (from Part 3.1)

---

### 4.4 Restore Backend Data if Modified

If the attacker modified or deleted data in backend services during the incident:

**DynamoDB:**
```bash
# Check Point-in-Time Recovery (PITR) status
aws dynamodb describe-continuous-backups \
  --table-name <table-name> \
  --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription'

# Restore table to point in time before attack
aws dynamodb restore-table-to-point-in-time \
  --source-table-name <table-name> \
  --target-table-name <table-name>-restored \
  --restore-date-time <timestamp-before-attack>
```

**S3:**
```bash
# Check S3 versioning status
aws s3api get-bucket-versioning --bucket <bucket-name>

# List object versions to find pre-attack version
aws s3api list-object-versions \
  --bucket <bucket-name> \
  --prefix <object-key>

# Restore previous version by copying it
aws s3api copy-object \
  --bucket <bucket-name> \
  --copy-source "<bucket-name>/<object-key>?versionId=<version-id>" \
  --key <object-key>
```

⚠️ **Warning:** Restoring data overwrites current state. Confirm which records were affected using access logs and Lambda logs from the investigation before restoring. Consult the application team to validate data integrity before and after restoration.

---

### 4.5 Verify Recovery

Monitor for 30+ minutes after restoring normal operations:

```bash
# Confirm API invocation count has returned to baseline
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name Count \
  --dimensions Name=ApiName,Value=<api-name> Name=Stage,Value=<stage-name> \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum

# Confirm Lambda invocation count and duration at baseline
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=<function-name> \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum

# Confirm no new unauthorized CloudTrail management events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::ApiGateway::RestApi \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 20
```
# MCP batch opportunity: run all CloudWatch metric queries in parallel

**Recovery is verified when ALL of the following are true:**
- [ ] API Gateway `Count` metric is at expected baseline for time of day
- [ ] Lambda invocation count and duration are at expected baseline
- [ ] Legitimate clients confirm API is functioning correctly
- [ ] No WAF blocks on legitimate client IPs
- [ ] CloudTrail shows no further unauthorized API Gateway management-plane changes
- [ ] Backend data spot-check confirms records are correct post-restoration
- [ ] All monitoring and alerting is re-armed and functioning

---

## Part 5: Post-Incident Activity

### 5.1 Document Lessons Learned

Create a post-incident report covering:
- **Timeline:** When did each phase of the attack and response occur?
- **Root cause:** How was the API breached? (leaked key, missing authorizer, WAF gap, injection vulnerability)
- **Impact:** What data was accessed or exfiltrated? Which clients/users were affected?
- **Response effectiveness:** What worked well? What slowed the response?
- **Recommendations:** Process, tooling, and configuration improvements

### 5.2 Retrospective Questions

- Could this attack have been detected earlier? What monitoring gap allowed it to go unnoticed?
- Was WAF enabled and properly configured before the incident? What rules were missing?
- Were authorizers enforced on all methods? Were there any unprotected endpoints?
- How quickly were logs available for investigation? Was access logging enabled pre-incident?
- Could the blast radius have been reduced with tighter IAM policies or usage plan quotas?

### 5.3 Update Defenses

Based on findings:
- [ ] Enable AWS WAF on all API Gateway stages with Core Rule Set (CRS) and Known Bad Inputs managed rule groups
- [ ] Enable access logging on all API Gateway stages with structured JSON format
- [ ] Enable execution logging on all API Gateway stages (ERROR level minimum)
- [ ] Enforce authorizer (IAM, Cognito, or Lambda) on all methods — remove `NONE` where not explicitly required
- [ ] Enable AWS Config rules: `api-gw-associated-with-waf`, `api-gw-execution-logging-enabled`, `api-gw-ssl-enabled`
- [ ] Enable Security Hub API Gateway controls (`APIGateway.1`, `APIGateway.2`, `APIGateway.9`)
- [ ] Implement API key rotation schedule
- [ ] Review and tighten IAM policies for all principals with `apigateway:*` permissions
- [ ] Consider enabling AWS WAF Bot Control for APIs exposed to the public internet
- [ ] Update this playbook with lessons learned

### 5.4 Regulatory Notifications

If required by your jurisdiction or compliance framework:
- [ ] Notify relevant authorities within required timeframe (e.g., GDPR 72-hour rule if EU personal data was exposed)
- [ ] Notify affected customers or users if PII was accessed via the API
- [ ] Document notification actions for compliance records (PCI-DSS, HIPAA, SOC 2)

---

## References

- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Amazon API Gateway Developer Guide](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [API Gateway Access Logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
- [API Gateway Security Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
