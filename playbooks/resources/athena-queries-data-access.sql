-- =============================================================================
-- Athena Queries: Unauthorized Data Access Investigation
-- Companion resource for IRP-DataAccess.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - S3 data events enabled in CloudTrail for sensitive buckets
--   - Replace placeholder values: BUCKET_NAME, TABLE_NAME, SUSPECT_PRINCIPAL,
--     START_TIME, END_TIME, ACCOUNT_ID
--   - Adjust table name (cloudtrail_logs) to match your Athena table
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. All S3 data access events for a specific bucket in a time window
-- Purpose: Establish the complete picture of who accessed the bucket and how
--          during the incident window. This is typically the first query to run.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn,
       userAgent, requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND requestParameters LIKE '%BUCKET_NAME%'
  AND eventName IN ('GetObject', 'HeadObject', 'ListObjects', 'ListObjectsV2',
                    'SelectObjectContent', 'CopyObject')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2. Top accessors of a bucket (identify anomalous principals)
-- Purpose: Quickly identify who is reading from the bucket and how much data
--          they transferred. Compare against known legitimate access patterns
--          to spot unauthorized principals.
-- ---------------------------------------------------------------------------
SELECT userIdentity.arn, sourceIPAddress, COUNT(*) as access_count,
       SUM(CAST(additionalEventData.bytesTransferredOut AS BIGINT)) as bytes_out
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND requestParameters LIKE '%BUCKET_NAME%'
  AND eventName = 'GetObject'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY userIdentity.arn, sourceIPAddress
ORDER BY access_count DESC;


-- ---------------------------------------------------------------------------
-- 3. Detect bulk data access (high-volume reads in short time)
-- Purpose: Identify principals performing bulk reads that exceed normal
--          operational patterns — a key indicator of data exfiltration.
--          Adjust the HAVING threshold based on normal bucket access volume.
-- ---------------------------------------------------------------------------
SELECT DATE_TRUNC('hour', from_iso8601_timestamp(eventTime)) as hour_bucket,
       userIdentity.arn, COUNT(*) as read_count
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters LIKE '%BUCKET_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY DATE_TRUNC('hour', from_iso8601_timestamp(eventTime)), userIdentity.arn
HAVING COUNT(*) > 100
ORDER BY hour_bucket ASC;


-- ---------------------------------------------------------------------------
-- 4. DynamoDB data access (Scan operations are a red flag for exfiltration)
-- Purpose: Identify data reads from DynamoDB tables. Scan operations reading
--          entire tables are particularly suspicious — legitimate applications
--          typically use Query or GetItem with specific key conditions.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn,
       requestParameters
FROM cloudtrail_logs
WHERE eventSource = 'dynamodb.amazonaws.com'
  AND eventName IN ('Scan', 'Query', 'BatchGetItem', 'GetItem')
  AND requestParameters LIKE '%TABLE_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 5. Secrets Manager / Parameter Store access
-- Purpose: Determine if the threat actor accessed stored secrets or
--          configuration parameters. Accessed secrets should be rotated
--          immediately during eradication.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn,
       requestParameters
FROM cloudtrail_logs
WHERE eventSource IN ('secretsmanager.amazonaws.com', 'ssm.amazonaws.com')
  AND eventName IN ('GetSecretValue', 'GetParameter', 'GetParameters',
                    'GetParametersByPath')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 6. All GetObject calls for a specific bucket, grouped by principal
-- Purpose: Provide a summary view showing which principals accessed the
--          bucket, how many objects they read, and their access window.
--          Useful for reporting and impact assessment.
-- ---------------------------------------------------------------------------
SELECT userIdentity.arn, sourceIPAddress, COUNT(*) as read_count,
       MIN(eventTime) as first_access, MAX(eventTime) as last_access
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters LIKE '%BUCKET_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY userIdentity.arn, sourceIPAddress
ORDER BY read_count DESC;


-- ---------------------------------------------------------------------------
-- 7. Detect data staging (copies to other buckets or accounts)
-- Purpose: Identify if the threat actor copied data to a location they
--          control — a staging step before exfiltration. Check for copies
--          to unfamiliar buckets or cross-account destinations.
-- ---------------------------------------------------------------------------
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       json_extract_scalar(requestParameters, '$.bucketName') as source_bucket,
       json_extract_scalar(requestParameters, '$.x-amz-copy-source') as copy_source
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('CopyObject', 'PutObject', 'UploadPart')
  AND userIdentity.arn = 'SUSPECT_PRINCIPAL'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 8. Identify specific objects accessed (what data was read)
-- Purpose: Determine exactly which objects the threat actor accessed.
--          Essential for data impact assessment and regulatory notification
--          decisions — you need to know what data was exposed.
-- ---------------------------------------------------------------------------
SELECT eventTime, json_extract_scalar(requestParameters, '$.key') as object_key,
       sourceIPAddress, userIdentity.arn
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters LIKE '%BUCKET_NAME%'
  AND userIdentity.arn = 'SUSPECT_PRINCIPAL'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 9. Detect bucket policy or ACL changes (threat actor granting access)
-- Purpose: Identify if the threat actor modified the bucket's access controls
--          to grant themselves (or others) persistent access. Policy changes
--          are a form of persistence that survives credential rotation.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl',
                    'PutObjectAcl', 'PutBucketPublicAccessBlock',
                    'DeleteBucketPublicAccessBlock')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 10. S3 server access log analysis
-- Purpose: S3 server access logs capture requests that CloudTrail data events
--          may miss (e.g., anonymous access, presigned URL usage). Query these
--          if you suspect access via presigned URLs or public exposure.
-- Note: Requires S3 access logs stored in an Athena-queryable format.
-- ---------------------------------------------------------------------------
SELECT request_datetime, remote_ip, requester, operation, key,
       http_status, bytes_sent, total_time
FROM s3_access_logs
WHERE bucket = 'AFFECTED_BUCKET'
  AND operation = 'REST.GET.OBJECT'
  AND request_datetime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY request_datetime ASC;


-- ---------------------------------------------------------------------------
-- 11. Check if the threat actor accessed other buckets
-- Purpose: Determine if the data access was limited to one bucket or if
--          the principal accessed additional data stores. Important for
--          scoping the full impact.
-- ---------------------------------------------------------------------------
SELECT DISTINCT json_extract_scalar(requestParameters, '$.bucketName') as bucket_accessed
FROM cloudtrail_logs
WHERE userIdentity.arn = 'SUSPECT_PRINCIPAL'
  AND eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME';


-- ---------------------------------------------------------------------------
-- 12. Check for data copies to threat-actor-controlled locations
-- Purpose: Identify if the threat actor created snapshots, copies, or
--          exports of data to locations outside your control. This confirms
--          exfiltration vs. in-place access.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, requestParameters
FROM cloudtrail_logs
WHERE userIdentity.arn = 'SUSPECT_PRINCIPAL'
  AND eventName IN ('CopyObject', 'PutObject', 'CreateSnapshot',
                    'CopySnapshot', 'ShareSnapshot')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
