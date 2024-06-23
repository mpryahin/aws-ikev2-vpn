variable "aws_region" {
  type        = string
  description = "The full name of the region to use"
  default     = "eu-west-2"
}

variable "aws_subnet_name" {
  description = "The VPN server public subnet name"
  type        = string
}

variable "aws_route53_zone_name" {
  description = "The public hosted zone name"
  type        = string
}

variable "vpn_server_domain_name" {
  description = "The VPN server fully qualified domain name"
  type        = string
}

variable "aws_instance_type" {
  description = "VPN server instance type"
  type        = string
  default     = "t4g.nano"
}

variable "aws_rsa_pub" {
  description = "key pair's public key to be registered with AWS to allow logging-in to EC2 instances"
  type        = string
}

variable "vpn_user_name" {
  description = "A VPN user name to be created"
  type        = string
}

variable "vpn_admin_email" {
  description = "An email address to be used by the certbot"
  type        = string
}
