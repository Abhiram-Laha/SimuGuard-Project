# Change Ticket: PR #4082
# Submitted by: DevOps Pipeline Team
# Reason: Allow analytics service to push logs to external webhook and write to S3 bucket.

resource "aws_security_group_rule" "allow_outbound_webhook" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  # Temporarily opened to 0.0.0.0/0 so external analytics webhook works without IP whitelisting
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-analytics-web-01"
}

resource "aws_iam_role_policy_attachment" "analytics_s3_access" {
  role       = "role-analytics-ingestion-svc"
  # Attached managed policy to quickly fix S3 AccessDenied error in staging
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
