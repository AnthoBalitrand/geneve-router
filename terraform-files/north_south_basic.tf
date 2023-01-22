provider "aws" {
  region = "eu-west-3"
}

variable "inspection_instances_key_name" {}

resource "tls_private_key" "inspection_instances_pk" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "inspection_instances_kp" {
  key_name = var.inspection_instances_key_name
  public_key = tls_private_key.inspection_instances_pk.public_key_openssh
}

data "aws_ami" "amzn2-kernel" {
  most_recent = true

  filter {
    name = "name"
    values = ["amzn2-ami-kernel-5.10-hvm*"]
  }

  filter {
    name = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["137112412989"]
}

resource "aws_vpc" "inspection_vpc" {
  cidr_block = "192.168.10.0/24"
  enable_dns_hostnames = false
  tags = {
    Name = "inspection_vpc"
  }
}

resource "aws_subnet" "inspection_subnet_1" {
  availability_zone = "eu-west-3a"
  cidr_block = "192.168.10.0/26"
  vpc_id = aws_vpc.inspection_vpc.id
  tags = {
    Name = "inspection_subnet_1"
  }
  map_public_ip_on_launch = true
}

resource "aws_subnet" "inspection_subnet_2" {
  availability_zone = "eu-west-3b"
  cidr_block = "192.168.10.64/26"
  vpc_id = aws_vpc.inspection_vpc.id
  tags = {
    Name = "inspection_subnet_2"
  }
  map_public_ip_on_launch = true
}

resource "aws_lb_target_group" "inspection_instances" {
  name = "inspectioninstances"
  port = 6081
  protocol = "GENEVE"
  vpc_id = aws_vpc.inspection_vpc.id
  target_type = "instance"

  health_check {
    port = 80
    protocol = "HTTP"
  }
}

resource "aws_lb_target_group_attachment" "inspection_gwlb_tg_attach_1" {
  target_group_arn = aws_lb_target_group.inspection_instances.arn
  target_id = aws_instance.inspection_instance_1.id
  port = 6081
}

resource "aws_lb_target_group_attachment" "inspection_gwlb_tg_attach_2" {
  target_group_arn = aws_lb_target_group.inspection_instances.arn
  target_id = aws_instance.inspection_instance_2.id
  port = 6081
}

resource "aws_instance" "inspection_instance_1" {
  ami = data.aws_ami.amzn2-kernel.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.inspection_instances_kp.key_name
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.inspection_instance_1_eni.id
  }
}

resource "aws_instance" "inspection_instance_2" {
  ami = data.aws_ami.amzn2-kernel.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.inspection_instances_kp.key_name
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.inspection_instance_2_eni.id
  }
}

resource "aws_network_interface" "inspection_instance_1_eni" {
  subnet_id = aws_subnet.inspection_subnet_1.id
  private_ips = ["192.168.10.4"]
}

resource "aws_network_interface" "inspection_instance_2_eni" {
  subnet_id = aws_subnet.inspection_subnet_2.id
  private_ips = ["192.168.10.68"]
}

resource "aws_lb" "inspection_gateway_lb" {
  load_balancer_type = "gateway"
  name = "inspectiongatewaylb"
  subnets = [aws_subnet.inspection_subnet_1.id, aws_subnet.inspection_subnet_2.id]
  tags = {
    Name = "inspection_gateway_lb"
  }
}

resource "aws_vpc_endpoint_service" "inspection_gwlb_endpointservice" {
  acceptance_required = false
  depends_on = [aws_lb.inspection_gateway_lb]
  gateway_load_balancer_arns = [aws_lb.inspection_gateway_lb.arn]
  tags = {
    Name = "inspection_gwlb_endpointservice"
  }
}

resource "aws_internet_gateway" "inspection_vpc_igw" {
  vpc_id = aws_vpc.inspection_vpc.id
  tags = {
    Name = "inspection_vpc_igw"
  }
}

resource "aws_default_route_table" "inspection_vpc_default_rt" {
  default_route_table_id = aws_vpc.inspection_vpc.default_route_table_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.inspection_vpc_igw.id
  }
  depends_on = [aws_internet_gateway.inspection_vpc_igw]
}

resource "aws_security_group" "inspection_instance_sg" {
  name = "inspection_instance_sg"
  description = "Allow SSH from remote IP + GWLB health check and traffic"
  vpc_id = aws_vpc.inspection_vpc.id
  ingress {
    description = "SSH from admin"
    from_port = 22
    protocol  = "tcp"
    to_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Health-check from LB target-group"
    from_port = 80
    protocol  = "tcp"
    to_port   = 80
    cidr_blocks = [aws_vpc.inspection_vpc.cidr_block]
  }
  ingress {
    description = "Geneve traffic from GWLB"
    from_port = 6081
    protocol  = "udp"
    to_port   = 6081
    cidr_blocks = [aws_vpc.inspection_vpc.cidr_block]
  }
  egress {
    from_port = 0
    protocol  = "-1"
    to_port   = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_interface_sg_attachment" "inspection_instance_1_sg_attachment" {
  security_group_id = aws_security_group.inspection_instance_sg.id
  network_interface_id = aws_network_interface.inspection_instance_1_eni.id
}

resource "aws_network_interface_sg_attachment" "inspection_instance_2_sg_attachment" {
  security_group_id = aws_security_group.inspection_instance_sg.id
  network_interface_id = aws_network_interface.inspection_instance_2_eni.id
}

resource "aws_lb_listener" "gwlb-listener" {
  load_balancer_arn = aws_lb.inspection_gateway_lb.arn

  default_action {
    target_group_arn = aws_lb_target_group.inspection_instances.arn
    type = "forward"
  }
}

output "private_key" {
  value = tls_private_key.inspection_instances_pk.private_key_pem
  sensitive = true
}