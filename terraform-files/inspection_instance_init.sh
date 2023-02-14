#!/bin/bash
yum -y install git gcc
amazon-linux-extras install python3.8 -y
git clone https://github.com/AnthoBalitrand/geneve-router.git
cd geneve-router || exit
pip3.8 install -r requirements.txt
python3.8 main.py -t -l info