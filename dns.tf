resource "aws_eip" "vpn_server" {
  vpc      = true
  tags = {
    Name = "ikev2-vpn-server"
  }
}

resource "aws_eip_association" "eip_vpn_server" {
  instance_id   = aws_instance.vpn_server.id
  allocation_id = aws_eip.vpn_server.id
}

data "aws_route53_zone" "public" {
  name          = var.aws_route53_zone_name
}

resource "aws_route53_record" "vpn_server" {
  zone_id       = data.aws_route53_zone.public.zone_id
  name          = var.vpn_server_domain_name
  type          = "A"
  ttl           = "300"
  records       = [aws_eip.vpn_server.public_ip]
}