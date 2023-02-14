provider "aws" {
  region = "eu-west-3"
}

variable "inspection_instances_key_name" {
  type = string
  default = "inspection_instances"
}

resource "tls_private_key" "inspection_instances_pk" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "inspection_instances_kp" {
  key_name = var.inspection_instances_key_name
  public_key = tls_private_key.inspection_instances_pk.public_key_openssh
}

resource "null_resource" "previous" {}

resource "time_sleep" "wait_3_minutes" {
  depends_on = [null_resource.previous]

  create_duration = "3m"
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

resource "aws_vpc" "public_vpc" {
  cidr_block = "10.0.10.0/24"
  enable_dns_hostnames = false
  tags = {
    Name = "public_vpc"
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

resource "aws_subnet" "public_subnet_1" {
  availability_zone = "eu-west-3a"
  cidr_block = "10.0.10.0/26"
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "public_subnet_1"
  }
  map_public_ip_on_launch = true
}

resource "aws_subnet" "public_subnet_2" {
  availability_zone = "eu-west-3b"
  cidr_block = "10.0.10.64/26"
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "public_subnet_2"
  }
  map_public_ip_on_launch = true
}

resource "aws_subnet" "gwlbe_subnet_1" {
  availability_zone = "eu-west-3a"
  cidr_block = "10.0.10.128/26"
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "gwlbe_subnet_1"
  }
  map_public_ip_on_launch = false
}

resource "aws_subnet" "gwlbe_subnet_2" {
  availability_zone = "eu-west-3b"
  cidr_block = "10.0.10.192/26"
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "gwlbe_subnet_2"
  }
  map_public_ip_on_launch = false
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
  user_data = file("inspection_instance_init.sh")
  tags = {
    Name = "Inspection_instance_1"
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
  user_data = file("inspection_instance_init.sh")
  tags = {
    Name = "Inspection_instance_2"
  }
}

resource "aws_instance" "public_instance_1" {
  ami = data.aws_ami.amzn2-kernel.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.inspection_instances_kp.key_name
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.public_instance_1_eni.id
  }
  user_data = file("public_instance_init.sh")
  tags = {
    Name = "Public_instance_1"
  }
  depends_on = [aws_instance.inspection_instance_1, aws_instance.inspection_instance_2, time_sleep.wait_3_minutes]
}

resource "aws_instance" "public_instance_2" {
  ami = data.aws_ami.amzn2-kernel.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.inspection_instances_kp.key_name
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.public_instance_2_eni.id
  }
  user_data = file("public_instance_init.sh")
  tags = {
    Name = "Public_instance_1"
  }
  depends_on = [aws_instance.inspection_instance_1, aws_instance.inspection_instance_2, time_sleep.wait_3_minutes]
}

resource "aws_network_interface" "inspection_instance_1_eni" {
  subnet_id = aws_subnet.inspection_subnet_1.id
  private_ips = ["192.168.10.4"]
}

resource "aws_network_interface" "inspection_instance_2_eni" {
  subnet_id = aws_subnet.inspection_subnet_2.id
  private_ips = ["192.168.10.68"]
}

resource "aws_network_interface" "public_instance_1_eni" {
  subnet_id = aws_subnet.public_subnet_1.id
  private_ips = ["10.0.10.4"]
}

resource "aws_network_interface" "public_instance_2_eni" {
  subnet_id = aws_subnet.public_subnet_2.id
  private_ips = ["10.0.10.68"]
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

resource "aws_vpc_endpoint" "public_gwlb_endpoint_1" {
  service_name = aws_vpc_endpoint_service.inspection_gwlb_endpointservice.service_name
  subnet_ids = [aws_subnet.gwlbe_subnet_1.id]
  vpc_endpoint_type = aws_vpc_endpoint_service.inspection_gwlb_endpointservice.service_type
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "inspection_gwlb_endpoint_1"
  }
}

resource "aws_vpc_endpoint" "public_gwlb_endpoint_2" {
  service_name = aws_vpc_endpoint_service.inspection_gwlb_endpointservice.service_name
  subnet_ids = [aws_subnet.gwlbe_subnet_2.id]
  vpc_endpoint_type = aws_vpc_endpoint_service.inspection_gwlb_endpointservice.service_type
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "inspection_gwlb_endpoint_2"
  }
}

resource "aws_internet_gateway" "inspection_vpc_igw" {
  vpc_id = aws_vpc.inspection_vpc.id
  tags = {
    Name = "inspection_vpc_igw"
  }
}

resource "aws_internet_gateway" "public_vpc_igw" {
  vpc_id = aws_vpc.public_vpc.id
  tags = {
    Name = "public_vpc_igw"
  }
}

resource "aws_default_route_table" "inspection_vpc_default_rt" {
  default_route_table_id = aws_vpc.inspection_vpc.default_route_table_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.inspection_vpc_igw.id
  }
  depends_on = [aws_internet_gateway.inspection_vpc_igw]
  tags = {
    Name = "inspection_vpc_default_rt"
  }
}

resource "aws_route_table" "gwlbe_subnets_rt" {
  vpc_id = aws_vpc.public_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.public_vpc_igw.id
  }
  tags = {
    Name = "gwlbe_subnets_rt"
  }
}

resource "aws_route_table" "public_subnet_1_rt" {
  vpc_id = aws_vpc.public_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    vpc_endpoint_id = aws_vpc_endpoint.public_gwlb_endpoint_1.id
  }
  tags = {
    Name = "public_subnet_1_rt"
  }
}

resource "aws_route_table" "public_subnet_2_rt" {
  vpc_id = aws_vpc.public_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    vpc_endpoint_id = aws_vpc_endpoint.public_gwlb_endpoint_2.id
  }
  tags = {
    Name = "public_subnet_2_rt"
  }
}


resource "aws_route_table" "gwlbe_rt" {
  vpc_id = aws_vpc.public_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.public_vpc_igw.id
  }
  tags = {
    Name = "public_vpc_gwlbe_rt"
  }
}

resource "aws_route_table" "igw_ingress_rt" {
  vpc_id = aws_vpc.public_vpc.id
  route {
    cidr_block = aws_subnet.public_subnet_1.cidr_block
    vpc_endpoint_id = aws_vpc_endpoint.public_gwlb_endpoint_1.id
  }
  route {
    cidr_block = aws_subnet.public_subnet_2.cidr_block
    vpc_endpoint_id = aws_vpc_endpoint.public_gwlb_endpoint_2.id
  }
  tags = {
    Name = "public_vpc_ingress_rt"
  }
  depends_on = [aws_vpc_endpoint.public_gwlb_endpoint_1, aws_vpc_endpoint.public_gwlb_endpoint_2]
}

resource "aws_route_table_association" "public_glwbe_subnet_1_association" {
  subnet_id = aws_subnet.gwlbe_subnet_1.id
  route_table_id = aws_route_table.gwlbe_subnets_rt.id
}

resource "aws_route_table_association" "public_glwbe_subnet_2_association" {
  subnet_id = aws_subnet.gwlbe_subnet_2.id
  route_table_id = aws_route_table.gwlbe_subnets_rt.id
}

resource "aws_route_table_association" "public_igw_ingress_1_association" {
  gateway_id = aws_internet_gateway.public_vpc_igw.id
  route_table_id = aws_route_table.igw_ingress_rt.id
}

resource "aws_route_table_association" "public_subnet_1_association" {
  subnet_id = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_subnet_1_rt.id
}

resource "aws_route_table_association" "public_subnet_2_association" {
  subnet_id = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_subnet_2_rt.id
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

resource "aws_security_group" "public_instance_sg" {
  name = "public_instance_sg"
  description = "Allow SSH from remote IP + HTTP access"
  vpc_id = aws_vpc.public_vpc.id
  ingress {
    description = "SSH from admin"
    from_port = 22
    protocol  = "tcp"
    to_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Public HTTP access"
    from_port = 80
    protocol  = "tcp"
    to_port   = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Public ICMP"
    from_port = -1
    protocol = "icmp"
    to_port = -1
    cidr_blocks = ["0.0.0.0/0"]
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

resource "aws_network_interface_sg_attachment" "public_instance_1_sg_attachment" {
  security_group_id = aws_security_group.public_instance_sg.id
  network_interface_id = aws_network_interface.public_instance_1_eni.id
}

resource "aws_network_interface_sg_attachment" "public_instance_2_sg_attachment" {
  security_group_id = aws_security_group.public_instance_sg.id
  network_interface_id = aws_network_interface.public_instance_2_eni.id
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