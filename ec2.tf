
data "aws_ami" "ubuntu" {
  owners = ["099720109477"]
  most_recent      = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

resource "aws_instance" "vpn_server" {
  ami                           = data.aws_ami.ubuntu.image_id
  instance_type                 = var.aws_instance_type
  associate_public_ip_address   = true
  vpc_security_group_ids        = [aws_security_group.private_vpn.id]
  key_name                      = var.aws_instance_ssh_key_name
  user_data                     = templatefile("cloud-init.yaml", { 
                                      vpn_host: var.vpn_server_domain_name, 
                                      vpn_user_name: var.vpn_user_name, 
                                      email: var.vpn_admin_email
                                  })
  subnet_id                     = data.aws_subnet.selected.id
  root_block_device {
    delete_on_termination = true
    volume_size           = 8
    volume_type           = "standard"
  }
  
  tags = {
    Name = "ikev2-vpn-server"
  }

  depends_on = [aws_route53_record.vpn_server]
}