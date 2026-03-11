# IAM Hardening and CloudTrail Logging
# Remediation for: anomalous IAM access key activity (persistence tactics)
# Affected resource: AWS::IAM::AccessKey:ASIATHVQLCBNELGA7B6K
#
# This file:
#   1. Defines an IAM user with a restricted policy that does not allow broad
#      access key management, preventing persistence via credential creation.
#   2. Enables CloudTrail for detailed logging of IAM and security-related API
#      calls so that anomalous activity can be detected and audited.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# S3 bucket to receive CloudTrail logs
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudtrail-iam-audit-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = {
    Name        = "CloudTrailIAMAuditLogs"
    Environment = "Security"
    Purpose     = "Centralized IAM audit logging"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_pab" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs_sse" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudTrail: multi-region trail capturing global (IAM) service events
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "iam_audit_trail" {
  name                          = "iam-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name        = "IAMAuditTrail"
    Environment = "Security"
    Purpose     = "Detect anomalous IAM / access key activity"
  }
}

# ---------------------------------------------------------------------------
# IAM user with restricted policy (no access key management permissions)
# ---------------------------------------------------------------------------

resource "aws_iam_user" "restricted_user" {
  name = "restricted-service-user"

  tags = {
    Name        = "RestrictedServiceUser"
    Environment = "Security"
    Purpose     = "Least-privilege user; no long-lived access key management"
  }
}

resource "aws_iam_user_policy" "restricted_user_policy" {
  name = "restricted-iam-actions"
  user = aws_iam_user.restricted_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "*"
      },
    ]
  })
}
