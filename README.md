# Terraform IKEv2 AWS Site-to-Site VPN Setup

## Table of contents

- [Description](#description)
- [VPN clients](#vpn-clients)
- [Configuration Details](#configuration-details)
- [Installation](#installation)

## Description

A terraform configuration to deploy a lightweight  site-to-site VPN  in AWS.  The VPN allows to securely access private VPC subnets without exposing network resources to the Internet. Used mostly for development purposes as a cheaper alternative to the AWS native managed site-to-site VPN service.

## VPN clients

The VPN is tested working with:

- **macOS 10.12 – 10.15, iOS 10 – 13** — Built-in clients. A .mobileconfig profile is generated for Mac and iOS, to set up secure ciphers and enable *Connect on demand* support.
- **Windows 10 Pro** — Built-in client. PowerShell commands are generated to configure the VPN and secure ciphers.
- **Ubuntu (17.04 and presumably others)** — Using strongSwan. A Bash script is generated to set this up.
- **Android** — Using the official strongSwan app.

## Configuration Details

The project creates the following AWS resources:

- An EC2 instance.
- A security group.
- An ssh key.
- An Elastic IP.
- A DNS record.

The EC2 Instance is initialised with a user-data script that pulls the main installation script via https protocol from this repository. To make sure the installation script is not malformed while in transit the user data-script validates it against the checksum that is passed as a terraform input variable.
The setup script employs [Strongswan](https://www.strongswan.org/) the open source IPsec-based VPN server, and is based on the [GitHub - jawj/IKEv2-setup](https://github.com/jawj/IKEv2-setup) project with subtle modifications to suit a non-interactive installation mode and to support AWS DNS configuration.

## Installation

Initialise a terraform working directory:

```bash
terraform init -backend-config=.backend.conf
```

Create an execution plan with changes that Terraform will make to your infrastructure.

```bash 
terraform plan
```

Apply the terraform configuration

```bash
terraform apply -auto-approve
```

Download a VPN client config files when setup script is finished. (These files become available only after the Terraform configuration has been provisioned, usually take a few minutes)

iOS/macOS:

```bash
ssh <user>@<vpn_domain_name> "sudo cat /home/root/vpn-ios-or-mac.mobileconfig" > vpn-ios-or-mac.mobileconfig
```

Ubuntu:

```bash
ssh <user>@<vpn_domain_name> "sudo cat /home/root/vpn-ubuntu-client.sh" > vpn-ubuntu-client.sh
```

Get VPN Credentials:

```bash
ssh <user>@<vpn_domain_name> "sudo cat /etc/ipsec.secrets" | tail -n+2 | awk '{print $1,$4}'
```
