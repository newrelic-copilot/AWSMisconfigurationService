# S3 Bucket Configuration
# Public write access has been remediated per security policy

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

variable "allowed_reader_arns" {
  description = "List of IAM principal ARNs allowed to read objects from the S3 bucket (e.g. arn:aws:iam::123456789012:role/reader-role)"
  type        = list(string)
}

variable "allowed_writer_arns" {
  description = "List of IAM principal ARNs allowed to write objects to the S3 bucket (e.g. arn:aws:iam::123456789012:role/writer-role)"
  type        = list(string)
}

# Misconfigured S3 Bucket with public access
resource "aws_s3_bucket" "misconfigured_bucket" {
  bucket = "my-misconfigured-bucket-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "MisconfiguredBucket"
    Environment = "SecurityTesting"
    Purpose     = "Security testing bucket"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# Public access block enabled to prevent public write access
resource "aws_s3_bucket_public_access_block" "misconfigured_pab" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACL set to private to prevent public write access
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

# Bucket policy restricts write access to specific IAM principal only
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
          AWS = var.allowed_reader_arns
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*",
        ]
      },
      {
        Sid    = "RestrictedWriteAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.allowed_writer_arns
        }
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
  value = "NOTE: This bucket has been remediated. Public access is blocked, ACL is private, and write access is restricted to specific IAM principals."
}
