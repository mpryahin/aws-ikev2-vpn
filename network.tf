data "aws_subnet" "selected" {
  filter {
    name   = "tag:Name"
    values = [var.aws_subnet_name]
  }
}

resource "aws_security_group" "private_vpn" {
  name        = "private_vpn"
  description = "IKEv2 VPN Server Security Group"
  vpc_id      = data.aws_subnet.selected.vpc_id

  tags = {
    Name = "ikev2-vpn-server"
  }
}

resource "aws_security_group_rule" "http_certbot_challenge" {
  type              = "ingress"
  from_port         = 0
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.private_vpn.id
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 0
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_vpn.id
}

resource "aws_security_group_rule" "ike" {
  type              = "ingress"
  from_port         = 0
  to_port           = 500
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.private_vpn.id
}

resource "aws_security_group_rule" "nat" {
  type              = "ingress"
  from_port         = 0
  to_port           = 4500
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.private_vpn.id
}

resource "aws_security_group_rule" "all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private_vpn.id
}
