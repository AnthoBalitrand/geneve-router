#!/bin/bash
sleep 2m
yum -y update
yum -y install httpd
systemctl start httpd
systemctl enable httpd