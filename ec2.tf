
data "aws_ami" "ubuntu" {
  owners      = ["099720109477"]
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-"]
  }
}

resource "aws_instance" "vpn_server" {
  ami                         = data.aws_ami.ubuntu.image_id
  instance_type               = var.aws_instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.private_vpn.id]
  key_name                    = aws_key_pair.main.key_name
  user_data = templatefile("cloud-init.yaml", {
    vpn_host : var.vpn_server_domain_name,
    vpn_user_name : var.vpn_user_name,
    email : var.vpn_admin_email
  })
  subnet_id = data.aws_subnet.selected.id
  root_block_device {
    delete_on_termination = true
    volume_size           = 8
    volume_type           = "gp3"
  }

  tags = {
    Name = "ikev2-vpn-server"
  }

  depends_on = [aws_route53_record.vpn_server]
}

resource "aws_key_pair" "main" {
  key_name   = "aws-main"
  public_key = var.aws_rsa_pub
}
