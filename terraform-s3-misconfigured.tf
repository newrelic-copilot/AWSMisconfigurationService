# S3 Bucket - Customer Invoices
# Remediated: public access blocked, ACL restricted, bucket policy scoped to authenticated principals only

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  description = "AWS region to deploy the bucket in"
  type        = string
  default     = "us-east-2"
}

variable "app_role_name" {
  description = "Name of the IAM role that requires read access to the customer invoices bucket"
  type        = string
  default     = "srx-demo-app-role"
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# S3 Bucket for customer invoices
resource "aws_s3_bucket" "customer_invoices" {
  bucket = "srx-demo-customer-invoices-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name        = "CustomerInvoices"
    Environment = "Demo"
    Purpose     = "Customer invoice storage"
  }
}

# Block all public access to the bucket
resource "aws_s3_bucket_public_access_block" "customer_invoices_pab" {
  bucket = aws_s3_bucket.customer_invoices.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "customer_invoices_ownership" {
  bucket = aws_s3_bucket.customer_invoices.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Bucket policy: restrict read access to the application role only
resource "aws_s3_bucket_policy" "customer_invoices_policy" {
  bucket     = aws_s3_bucket.customer_invoices.id
  depends_on = [aws_s3_bucket_public_access_block.customer_invoices_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReadForApplicationRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.app_role_name}"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.customer_invoices.arn,
          "${aws_s3_bucket.customer_invoices.arn}/*",
        ]
      },
    ]
  })
}

# Output the bucket name and URL
output "bucket_name" {
  value = aws_s3_bucket.customer_invoices.id
}

output "bucket_domain_name" {
  value = aws_s3_bucket.customer_invoices.bucket_domain_name
}
