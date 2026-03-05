# S3 Bucket Configuration - Security hardened
# Public access is blocked and bucket policies restrict access to trusted principals only

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-2"
}

locals {
  customer_invoices_bucket = "srx-demo-customer-invoices-222634381402-us-east-2"
  hackathon_bucket         = "aws-test-hackathon-bucket-8"
}

# S3 Bucket
resource "aws_s3_bucket" "misconfigured_bucket" {
  bucket = "my-misconfigured-bucket-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "MisconfiguredBucket"
    Environment = "SecurityTesting"
    Purpose     = "Intentionally vulnerable for testing"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "misconfigured_pab" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Private ACL
resource "aws_s3_bucket_acl" "misconfigured_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.s3_bucket_acl_ownership]
  bucket     = aws_s3_bucket.misconfigured_bucket.id
  acl        = "private"
}

resource "aws_s3_bucket_ownership_controls" "s3_bucket_acl_ownership" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# MISCONFIGURATION 3: No server-side encryption
# (Default encryption is intentionally not configured)

# MISCONFIGURATION 4: No versioning enabled
resource "aws_s3_bucket_versioning" "misconfigured_versioning" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  versioning_configuration {
    status = "Disabled"
  }
}

# MISCONFIGURATION 5: No access logging
# (Logging is intentionally not configured)

# Bucket policy restricting access to trusted IAM principals only
resource "aws_s3_bucket_policy" "misconfigured_policy" {
  bucket     = aws_s3_bucket.misconfigured_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.misconfigured_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedReadAccess"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*"
        ]
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# Output the bucket name and URL
output "bucket_name" {
  value = aws_s3_bucket.misconfigured_bucket.id
}

output "bucket_domain_name" {
  value = aws_s3_bucket.misconfigured_bucket.bucket_domain_name
}

output "security_warnings" {
  value = "NOTE: This bucket has public access blocked and uses a restricted bucket policy."
}

# -----------------------------------------------------------------------
# Remediation for affected buckets:
#   - srx-demo-customer-invoices-222634381402-us-east-2
#   - aws-test-hackathon-bucket-8
# -----------------------------------------------------------------------

resource "aws_s3_bucket_public_access_block" "customer_invoices_pab" {
  bucket = local.customer_invoices_bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "customer_invoices_policy" {
  bucket     = local.customer_invoices_bucket
  depends_on = [aws_s3_bucket_public_access_block.customer_invoices_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedReadAccess"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${local.customer_invoices_bucket}",
          "arn:aws:s3:::${local.customer_invoices_bucket}/*"
        ]
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "hackathon_bucket_pab" {
  bucket = local.hackathon_bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "hackathon_bucket_policy" {
  bucket     = local.hackathon_bucket
  depends_on = [aws_s3_bucket_public_access_block.hackathon_bucket_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedReadAccess"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${local.hackathon_bucket}",
          "arn:aws:s3:::${local.hackathon_bucket}/*"
        ]
      }
    ]
  })
}
