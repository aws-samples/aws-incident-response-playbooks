-- =============================================================================
-- Athena Queries: Personal Data Breach Investigation
-- Companion resource for IRP-PersonalDataBreach.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - CloudTrail S3 data events enabled on buckets containing personal data
--   - Replace placeholder values: customer-pii-bucket, START_TIME, END_TIME,
--     account IDs, and role ARNs with your actual values
--   - Adjust table name (cloudtrail_logs) to match your Athena table
-- =============================================================================


-- ---------------------------------------------------------------------------
-- SECTION 1: Evidence Collection Queries
-- Purpose: Gather forensic evidence for regulatory investigation
-- Context: Run these early in the incident to preserve evidence before any
--          remediation actions that might alter the audit trail
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 1.1 All S3 data access events on buckets tagged as containing personal data
-- Purpose: Broad capture of all access events on PII-classified buckets during
--          the incident window. Use this as your baseline evidence set.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn AS accessor,
       userIdentity.accountId AS accessor_account,
       requestParameters.bucketName AS bucket,
       requestParameters.key AS object_key,
       sourceIPAddress, userAgent,
       additionalEventData.bytesTransferredOut AS bytes_transferred,
       errorCode
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('GetObject', 'SelectObjectContent', 'CopyObject',
                    'HeadObject', 'ListObjects', 'ListObjectsV2')
  AND requestParameters.bucketName IN ('customer-pii-bucket', 'hr-records-bucket',
                                        'health-data-bucket')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 1.2 Identify cross-account access to personal data buckets
-- Purpose: Detect access from accounts outside the data-owning organization.
--          Cross-account access is a strong indicator of unauthorized disclosure.
-- ---------------------------------------------------------------------------
SELECT eventTime, userIdentity.arn AS accessor,
       userIdentity.accountId AS accessor_account,
       requestParameters.bucketName AS bucket,
       requestParameters.key AS object_key,
       sourceIPAddress,
       additionalEventData.bytesTransferredOut AS bytes_out
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND userIdentity.accountId != '123456789012'  -- Replace with bucket owner account
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 1.3 Estimate number of unique records/individuals affected
-- Purpose: Provide the Privacy Officer with a defensible estimate of affected
--          individual count for regulatory notification. Based on object count
--          and known record density per file type.
-- ---------------------------------------------------------------------------
SELECT requestParameters.bucketName AS bucket,
       COUNT(DISTINCT requestParameters.key) AS unique_objects_accessed,
       COUNT(*) AS total_access_events,
       SUM(CAST(additionalEventData.bytesTransferredOut AS BIGINT)) AS total_bytes,
       MIN(eventTime) AS first_access,
       MAX(eventTime) AS last_access
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND userIdentity.arn = 'arn:aws:iam::999888777666:role/SuspiciousRole'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
GROUP BY requestParameters.bucketName;


-- ---------------------------------------------------------------------------
-- 1.4 Detect bulk download patterns (potential exfiltration)
-- Purpose: Flag any principal downloading more than 100 objects in a 1-hour
--          window. Bulk access to PII-classified buckets is a strong indicator
--          of data exfiltration requiring regulatory notification.
-- ---------------------------------------------------------------------------
SELECT userIdentity.arn AS accessor,
       DATE_TRUNC('hour', from_iso8601_timestamp(eventTime)) AS hour_window,
       COUNT(*) AS objects_accessed,
       SUM(CAST(additionalEventData.bytesTransferredOut AS BIGINT)) AS total_bytes
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
GROUP BY userIdentity.arn, DATE_TRUNC('hour', from_iso8601_timestamp(eventTime))
HAVING COUNT(*) > 100
ORDER BY objects_accessed DESC;


-- ---------------------------------------------------------------------------
-- 1.5 Macie finding correlation with CloudTrail access
-- Purpose: Correlate Macie-identified PII objects with CloudTrail access events
--          to determine whether objects *confirmed to contain personal data* were
--          actually accessed during the incident window.
-- Usage:  Export Macie findings first to identify object keys, then insert them
--          into the IN clause below.
-- ---------------------------------------------------------------------------
SELECT ct.eventTime, ct.userIdentity.arn AS accessor,
       ct.requestParameters.key AS object_key,
       ct.sourceIPAddress,
       ct.additionalEventData.bytesTransferredOut AS bytes_out,
       ct.userAgent
FROM cloudtrail_logs ct
WHERE ct.eventSource = 's3.amazonaws.com'
  AND ct.eventName = 'GetObject'
  AND ct.requestParameters.bucketName = 'customer-pii-bucket'
  AND ct.requestParameters.key IN (
    -- Insert object keys from Macie findings that contain PII
    'data/customers/export-20260501.csv',
    'data/customers/full-extract.json.gz',
    'backups/db-snapshot-customers-20260515.sql'
  )
  AND ct.eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND ct.errorCode IS NULL
ORDER BY ct.eventTime ASC;


-- ---------------------------------------------------------------------------
-- SECTION 2: Scope Determination Queries
-- Purpose: Help the Privacy Officer determine the full scope of the breach
--          for notification obligation assessment
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 2.1 All access by the suspect principal on the affected bucket
-- Purpose: Complete picture of what the unauthorized accessor touched.
--          Feed results to Privacy Officer for notification scope.
-- ---------------------------------------------------------------------------
SELECT eventTime, userIdentity.arn AS accessor_arn,
       userIdentity.accountId AS accessor_account,
       requestParameters.bucketName AS bucket,
       requestParameters.key AS object_key,
       sourceIPAddress, userAgent,
       additionalEventData.bytesTransferredOut AS bytes_out
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('GetObject', 'SelectObjectContent', 'HeadObject')
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2.2 Data volume determination by suspect principal
-- Purpose: Quantify total data accessed for regulatory notification content.
--          Regulators require "approximate number of records" in notifications.
-- ---------------------------------------------------------------------------
SELECT requestParameters.bucketName AS bucket,
       COUNT(DISTINCT requestParameters.key) AS unique_objects_accessed,
       COUNT(*) AS total_get_requests,
       SUM(CAST(additionalEventData.bytesTransferredOut AS BIGINT)) AS total_bytes_out
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND userIdentity.arn = 'arn:aws:iam::999888777666:role/SuspiciousRole'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
GROUP BY requestParameters.bucketName;


-- ---------------------------------------------------------------------------
-- 2.3 Exfiltration indicators — access from non-AWS IP addresses
-- Purpose: Determine if data left the AWS environment. This is the critical
--          question for notification obligations. Data accessed from non-AWS
--          IPs is a strong indicator of exfiltration.
-- Note:   This is a heuristic — some AWS services use public IPs. Cross-
--          reference with known corporate/VPN egress ranges.
-- ---------------------------------------------------------------------------
SELECT eventTime, sourceIPAddress, userIdentity.arn,
       requestParameters.key, additionalEventData.bytesTransferredOut
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
  AND sourceIPAddress NOT LIKE '10.%'
  AND sourceIPAddress NOT LIKE '172.%'
  AND sourceIPAddress NOT LIKE '192.168.%'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2.4 Configuration changes to the affected bucket during incident window
-- Purpose: Detect if the threat actor modified bucket policies, ACLs, or
--          replication rules to facilitate exfiltration or cover tracks.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn AS actor,
       sourceIPAddress, requestParameters, responseElements
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPolicy', 'DeleteBucketPolicy',
                    'PutBucketAcl', 'PutBucketReplication',
                    'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock')
  AND requestParameters.bucketName = 'customer-pii-bucket'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- SECTION 3: GuardDuty and Macie Evidence Export (CLI)
-- Purpose: Export findings as evidence for regulatory investigation
-- ---------------------------------------------------------------------------

-- Note: These are AWS CLI commands, not SQL. Run in your terminal.
--
-- List S3-related exfiltration findings:
-- aws guardduty list-findings \
--   --detector-id DETECTOR_ID \
--   --finding-criteria '{
--     "Criterion": {
--       "type": {
--         "Eq": ["Exfiltration:S3/MaliciousIPCaller",
--                "Exfiltration:S3/AnomalousBehavior",
--                "UnauthorizedAccess:S3/TorIPCaller"]
--       },
--       "severity": {"Gte": 7}
--     }
--   }' \
--   --region us-east-1
--
-- Get full finding details for regulatory evidence:
-- aws guardduty get-findings \
--   --detector-id DETECTOR_ID \
--   --finding-ids FINDING_ID_1 FINDING_ID_2 \
--   --region us-east-1 | tee guardduty-findings-export.json
--
-- List Macie findings for affected bucket:
-- aws macie2 list-findings \
--   --finding-criteria '{
--     "criterion": {
--       "resourcesAffected.s3Bucket.name": {
--         "eq": ["customer-pii-bucket"]
--       },
--       "category": {
--         "eq": ["CLASSIFICATION"]
--       }
--     }
--   }' \
--   --region us-east-1
--
-- Get detailed Macie finding information:
-- aws macie2 get-findings \
--   --finding-ids FINDING_ID_1 FINDING_ID_2 \
--   --region us-east-1 | tee macie-findings-export.json
