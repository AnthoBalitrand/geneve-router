#!/bin/bash
yum -y update
yum -y install httpd
systemctl start httpd
systemctl enable httpd