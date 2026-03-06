# Intentionally Misconfigured S3 Bucket - FOR SECURITY TESTING ONLY
# This file contains multiple security misconfigurations and should NOT be used in production

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

variable "allowed_writer_arn" {
  description = "IAM ARN of the principal allowed to read/write objects in the S3 bucket. Must be a specific IAM user or role ARN."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:(user|role)/", var.allowed_writer_arn))
    error_message = "allowed_writer_arn must be a valid IAM user or role ARN (e.g. arn:aws:iam::123456789012:role/MyRole)."
  }
}

# Misconfigured S3 Bucket with public access
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

# Block all public access to prevent public write (and read) access
resource "aws_s3_bucket_public_access_block" "misconfigured_pab" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACL set to private to prevent public write/read access
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

# Bucket policy restricted to specific IAM role - no public or wildcard principals
resource "aws_s3_bucket_policy" "misconfigured_policy" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.misconfigured_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedReadWriteDelete"
        Effect = "Allow"
        Principal = {
          AWS = [var.allowed_writer_arn]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*",
        ]
      },
    ]
  })
}

# Output the bucket name and URL
output "bucket_name" {
  value = aws_s3_bucket.misconfigured_bucket.id
}

output "bucket_domain_name" {
  value = aws_s3_bucket.misconfigured_bucket.bucket_domain_name
}

output "security_warnings" {
  value = "NOTE: Public write access has been blocked. Only the IAM principal specified in var.allowed_writer_arn has read/write access to this bucket."
}
