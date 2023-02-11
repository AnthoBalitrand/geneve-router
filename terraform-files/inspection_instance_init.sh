#!/bin/bash
yum -y install git
amazon-linux-extras install python3.8
git clone https://github.com/AnthoBalitrand/geneve-router.git
cd geneve-router || exit
pip3.8 install -r requirements.txt
python3.8 main.py