-- =============================================================================
-- Athena Queries: DoS / DDoS Investigation
-- Companion resource for IRP-DoS.md
-- =============================================================================
-- Prerequisites:
--   - CloudFront access logs delivered to S3 and queryable via Athena
--   - WAF logs delivered to S3 and queryable via Athena
--   - VPC Flow Logs delivered to S3 and queryable via Athena
--   - Replace placeholder values: date ranges, epoch timestamps, target IPs
--   - Adjust table names to match your Athena tables
-- =============================================================================


-- ---------------------------------------------------------------------------
-- SECTION 1: CloudFront Access Log Queries
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 1.1 Top source IPs by request volume during attack window
-- Purpose: Identify the highest-volume sources contributing to the attack.
--   Helps prioritize IP blocklist entries and understand attack distribution.
-- ---------------------------------------------------------------------------
SELECT "c-ip" AS source_ip,
       COUNT(*) AS request_count,
       COUNT(DISTINCT "cs-uri-stem") AS unique_paths,
       AVG("time-taken") AS avg_response_time_ms
FROM cloudfront_logs
WHERE date BETWEEN DATE '2026-01-01' AND DATE '2026-01-01'
  AND time BETWEEN '14:00:00' AND '15:00:00'
GROUP BY "c-ip"
HAVING COUNT(*) > 1000
ORDER BY request_count DESC
LIMIT 50;


-- ---------------------------------------------------------------------------
-- 1.2 Application-layer attack pattern detection (single URI targeted)
-- Purpose: Identify which endpoints are being targeted and whether the attack
--   is focused on expensive/slow endpoints (API abuse pattern) vs. broad flood.
-- ---------------------------------------------------------------------------
SELECT "cs-uri-stem" AS target_path,
       "cs-method" AS http_method,
       COUNT(*) AS request_count,
       COUNT(DISTINCT "c-ip") AS unique_sources,
       SUM(CASE WHEN "sc-status" >= 500 THEN 1 ELSE 0 END) AS error_5xx_count
FROM cloudfront_logs
WHERE date = DATE '2026-01-01'
  AND time BETWEEN '14:00:00' AND '15:00:00'
GROUP BY "cs-uri-stem", "cs-method"
ORDER BY request_count DESC
LIMIT 20;


-- ---------------------------------------------------------------------------
-- 1.3 Top source IPs with 5xx correlation and response time
-- Purpose: Extended version of 1.1 with percentile response time and 5xx
--   correlation. Useful for identifying sources that are actually causing
--   backend saturation vs. those just adding volume.
-- ---------------------------------------------------------------------------
SELECT "c-ip" AS source_ip,
       COUNT(*) AS total_requests,
       COUNT(DISTINCT "cs-uri-stem") AS unique_uris,
       SUM(CASE WHEN "sc-status" >= 500 THEN 1 ELSE 0 END) AS requests_causing_5xx,
       APPROX_PERCENTILE("time-taken", 0.95) AS p95_response_ms
FROM cloudfront_logs
WHERE date = DATE '2026-01-01'
  AND time BETWEEN '14:00:00' AND '16:00:00'
GROUP BY "c-ip"
HAVING COUNT(*) > 500
ORDER BY total_requests DESC
LIMIT 100;


-- ---------------------------------------------------------------------------
-- 1.4 User-Agent distribution during attack window
-- Purpose: Identify attack tools or botnets by User-Agent fingerprint.
--   Legitimate traffic typically has diverse user agents; botnets often share
--   a common (or absent) user agent string.
-- ---------------------------------------------------------------------------
SELECT "cs(User-Agent)" AS user_agent,
       COUNT(*) AS request_count,
       COUNT(DISTINCT "c-ip") AS unique_ips
FROM cloudfront_logs
WHERE date = DATE '2026-01-01'
  AND time BETWEEN '14:00:00' AND '16:00:00'
GROUP BY "cs(User-Agent)"
ORDER BY request_count DESC
LIMIT 20;


-- ---------------------------------------------------------------------------
-- SECTION 2: WAF Log Queries
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 2.1 Blocked and counted requests during attack
-- Purpose: Understand which WAF rules are triggering, which IPs are being
--   blocked, and which URIs are targeted. Helps assess rule effectiveness
--   and identify gaps where attack traffic is getting through.
-- ---------------------------------------------------------------------------
SELECT httprequest.clientip AS source_ip,
       httprequest.uri AS request_uri,
       httprequest.httpmethod AS method,
       action,
       terminatingruleid AS rule_triggered,
       COUNT(*) AS request_count
FROM waf_logs
WHERE timestamp BETWEEN 1716904800000 AND 1716908400000
GROUP BY httprequest.clientip, httprequest.uri,
         httprequest.httpmethod, action, terminatingruleid
ORDER BY request_count DESC
LIMIT 100;


-- ---------------------------------------------------------------------------
-- 2.2 Rate-based rule effectiveness analysis
-- Purpose: Evaluate how well rate-based rules performed during the attack.
--   Shows whether rules triggered appropriately and blocked attack traffic,
--   or if thresholds need adjustment.
-- ---------------------------------------------------------------------------
SELECT from_unixtime(timestamp/1000) AS event_time,
       action,
       terminatingruleid,
       httprequest.clientip AS source_ip,
       httprequest.country AS country,
       httprequest.uri AS uri,
       COUNT(*) AS request_count
FROM waf_logs
WHERE timestamp BETWEEN 1716904800000 AND 1716915600000
GROUP BY from_unixtime(timestamp/1000), action, terminatingruleid,
         httprequest.clientip, httprequest.country, httprequest.uri
ORDER BY request_count DESC
LIMIT 200;


-- ---------------------------------------------------------------------------
-- SECTION 3: VPC Flow Log Queries
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 3.1 Volumetric attack sources (high packet/byte count)
-- Purpose: Identify Layer 3/4 volumetric attack sources by total packet and
--   byte volume. Useful for NACLs and understanding attack magnitude when
--   traffic bypasses CloudFront (direct-to-origin attacks).
-- ---------------------------------------------------------------------------
SELECT srcaddr, dstaddr, dstport, protocol,
       SUM(packets) AS total_packets,
       SUM(bytes) AS total_bytes,
       COUNT(*) AS flow_records
FROM vpc_flow_logs
WHERE start >= 1716904800  -- epoch timestamp for attack window start
  AND "end" <= 1716908400  -- epoch timestamp for attack window end
  AND action = 'ACCEPT'
GROUP BY srcaddr, dstaddr, dstport, protocol
HAVING SUM(packets) > 100000
ORDER BY total_packets DESC
LIMIT 50;


-- ---------------------------------------------------------------------------
-- 3.2 Attack patterns by protocol and port
-- Purpose: Identify which protocols and ports are targeted to characterize
--   the attack type (UDP flood, SYN flood, DNS amplification, etc.) and
--   estimate total attack bandwidth.
-- ---------------------------------------------------------------------------
SELECT dstport, protocol,
       COUNT(DISTINCT srcaddr) AS unique_sources,
       SUM(packets) AS total_packets,
       SUM(bytes) / 1073741824.0 AS total_gb,
       SUM(bytes) / NULLIF(MAX("end") - MIN(start), 0) AS bytes_per_second
FROM vpc_flow_logs
WHERE start >= 1716904800
  AND "end" <= 1716915600
  AND dstaddr = '10.0.1.100'  -- replace with target IP
  AND action = 'ACCEPT'
GROUP BY dstport, protocol
ORDER BY total_packets DESC;


-- ---------------------------------------------------------------------------
-- SECTION 4: CloudWatch Logs Insights (ALB Request Logs)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 4.1 Request patterns causing backend saturation
-- Purpose: Identify which client IPs and request URLs are generating 5xx
--   errors or excessive processing time. Helps focus WAF rules on the
--   specific request patterns causing application impact.
-- Note: Run this in CloudWatch Logs Insights, not Athena.
-- ---------------------------------------------------------------------------
-- fields @timestamp, elb_status_code, target_status_code,
--        request_url, client_ip, target_processing_time
-- | filter elb_status_code >= 500 OR target_processing_time > 5
-- | stats count() as error_count by request_url, client_ip
-- | sort error_count desc
-- | limit 50


-- ---------------------------------------------------------------------------
-- SECTION 5: GuardDuty Finding Queries (CLI reference)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 5.1 List DoS-related GuardDuty findings
-- Purpose: Identify if GuardDuty has detected your infrastructure
--   participating in (outbound) DoS activity, which would indicate
--   resource compromise rather than being a target.
-- Note: Run via AWS CLI, not Athena.
-- ---------------------------------------------------------------------------
-- aws guardduty list-findings \
--   --detector-id DETECTOR_ID \
--   --finding-criteria '{
--     "Criterion": {
--       "type": {
--         "Eq": [
--           "Backdoor:EC2/DenialOfService.Tcp",
--           "Backdoor:EC2/DenialOfService.Udp",
--           "Backdoor:EC2/DenialOfService.Dns",
--           "Impact:EC2/PortSweep"
--         ]
--       }
--     }
--   }' \
--   --region us-east-1
--
-- aws guardduty get-findings \
--   --detector-id DETECTOR_ID \
--   --finding-ids FINDING_ID_1 FINDING_ID_2
