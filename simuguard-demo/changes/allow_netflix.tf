# Change Ticket: PR #4101
# Submitted by: DevOps Pipeline Team
# Reason: Allow office guest network to access Netflix streaming service.

resource "aws_security_group_rule" "allow_outbound_netflix" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  # Temporarily opened to netflix.com so Netflix works without IP whitelisting (Netflix IPs change frequently)
  destination       = ["netflix.com"]
  security_group_id = "sg-guest-network-01"
}
