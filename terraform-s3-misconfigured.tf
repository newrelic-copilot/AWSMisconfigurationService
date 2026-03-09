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

# ACL restricted to bucket-owner-full-control only
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

# Bucket policy restricted to deny all public write access
resource "aws_s3_bucket_policy" "misconfigured_policy" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublicWrite"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
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
  value = "NOTE: Public write access has been blocked on this bucket."
}

# Block public access for the additional affected buckets identified in the security finding
data "aws_s3_bucket" "srx_demo_customer_invoices" {
  bucket = "srx-demo-customer-invoices-222634381402-us-east-2"
}

resource "aws_s3_bucket_public_access_block" "srx_demo_customer_invoices_pab" {
  bucket = data.aws_s3_bucket.srx_demo_customer_invoices.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_s3_bucket" "aws_test_hackathon_bucket_8" {
  bucket = "aws-test-hackathon-bucket-8"
}

resource "aws_s3_bucket_public_access_block" "aws_test_hackathon_bucket_8_pab" {
  bucket = data.aws_s3_bucket.aws_test_hackathon_bucket_8.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
