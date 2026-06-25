-- =============================================================================
-- Athena Queries: IAM Credential Compromise Investigation
-- Companion resource for IRP-CredCompromise.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - Replace placeholder values: AKIAIOSFODNN7EXAMPLE, START_TIME, END_TIME
--   - Adjust table name (cloudtrail_logs) to match your Athena table
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. All API calls made by a specific access key in a time window
-- Purpose: Establish the full scope of activity for the credential under review
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent,
       requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2. Unique source IPs and user agents for a credential
-- Purpose: Distinguish legitimate usage from unauthorized usage by comparing
--          known IPs (corporate egress, VPN) to unfamiliar ones
-- ---------------------------------------------------------------------------
SELECT sourceIPAddress, userAgent, COUNT(*) as call_count,
       MIN(eventTime) as first_seen, MAX(eventTime) as last_seen
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY sourceIPAddress, userAgent
ORDER BY first_seen ASC;


-- ---------------------------------------------------------------------------
-- 3. Persistence mechanisms created by the principal under investigation
-- Purpose: Identify if new access paths (users, roles, keys, functions) were
--          created that would survive credential deactivation
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventName IN ('CreateUser', 'CreateRole', 'CreateAccessKey',
                    'CreateLoginProfile', 'AttachUserPolicy', 'AttachRolePolicy',
                    'PutUserPolicy', 'PutRolePolicy', 'UpdateAssumeRolePolicy',
                    'CreateFunction', 'UpdateFunctionCode', 'AddPermission',
                    'CreateEventSourceMapping', 'PutBucketPolicy',
                    'CreateTrail', 'StopLogging', 'DeleteTrail')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 4. Data access events (S3, DynamoDB, Secrets Manager, SSM)
-- Purpose: Determine if sensitive data was accessed by the credential
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, requestParameters, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventSource IN ('s3.amazonaws.com', 'dynamodb.amazonaws.com',
                      'secretsmanager.amazonaws.com', 'ssm.amazonaws.com')
  AND eventName IN ('GetObject', 'GetItem', 'BatchGetItem', 'GetSecretValue',
                    'GetParameter', 'GetParameters')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 5. Cross-account role assumptions from the credential
-- Purpose: Identify lateral movement to other AWS accounts
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, requestParameters, responseElements,
       sourceIPAddress, recipientAccountId
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventName = 'AssumeRole'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 6. Error events (failed API calls indicate reconnaissance or permission testing)
-- Purpose: Understand what the credential attempted but was denied
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, errorCode, errorMessage, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND errorCode IS NOT NULL
  AND errorCode != ''
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
