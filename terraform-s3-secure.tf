# Secure S3 Bucket Configuration - Remediation for public write access
# Addresses: srx-demo-customer-invoices-222634381402-us-east-2 and aws-test-hackathon-bucket-8

# ─── srx-demo-customer-invoices-222634381402-us-east-2 ───────────────────────

resource "aws_s3_bucket" "customer_invoices" {
  bucket = "srx-demo-customer-invoices-222634381402-us-east-2"

  tags = {
    Name        = "CustomerInvoices"
    Environment = "Production"
  }
}

resource "aws_s3_bucket_public_access_block" "customer_invoices_pab" {
  bucket = aws_s3_bucket.customer_invoices.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "customer_invoices_ownership" {
  bucket = aws_s3_bucket.customer_invoices.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "customer_invoices_policy" {
  bucket     = aws_s3_bucket.customer_invoices.id
  depends_on = [aws_s3_bucket_public_access_block.customer_invoices_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublicWrite"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutObjectAcl"
        ]
        Resource = [
          aws_s3_bucket.customer_invoices.arn,
          "${aws_s3_bucket.customer_invoices.arn}/*",
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalType" = "Anonymous"
          }
        }
      },
    ]
  })
}

# ─── aws-test-hackathon-bucket-8 ─────────────────────────────────────────────

resource "aws_s3_bucket" "hackathon_bucket" {
  bucket = "aws-test-hackathon-bucket-8"

  tags = {
    Name        = "HackathonTestBucket"
    Environment = "Testing"
  }
}

resource "aws_s3_bucket_public_access_block" "hackathon_bucket_pab" {
  bucket = aws_s3_bucket.hackathon_bucket.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "hackathon_bucket_ownership" {
  bucket = aws_s3_bucket.hackathon_bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "hackathon_bucket_policy" {
  bucket     = aws_s3_bucket.hackathon_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.hackathon_bucket_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublicWrite"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutObjectAcl"
        ]
        Resource = [
          aws_s3_bucket.hackathon_bucket.arn,
          "${aws_s3_bucket.hackathon_bucket.arn}/*",
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalType" = "Anonymous"
          }
        }
      },
    ]
  })
}
