# AWS GWLB Geneve-Router

This is a pure educational / testing purposes project. 
**This should never be used for production.**

More information about this can be found here : [www.anthony-balitrand.fr](https://www.anthony-balitrand.fr/2023/02/18/have-fun-with-aws-gwlb-i-wrote-a-geneve-router-in-python/)

## Installation

```bash
git clone https://github.com/AnthoBalitrand/geneve-router.git
cd geneve-router
pip3 install -r requirements.txt
```

A Terraform stack file is available in the project folders to deploy it easily with a pre-built topology if you just want to understand how GWLB works with the Geneve protocol. See below for more details. 

## Usage

The --help keyword will give you all the necessary details. 

Note that this project has been built to work only with AWS GWLB. You might have issues using it with any other kind of Geneve endpoint. 

```bash
python3 main.py --help

usage: geneve-router [-h] [--no-daemon] [-l LOG_LEVEL] [-f LOG_FILE] [-t] [-u]

Geneve router for AWS GWLB

optional arguments:
  -h, --help            show this help message and exit
  --no-daemon           Do not start the Geneve router as a daemon
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Log level. If used without --no-daemon, will force logging to logging.log
  -f LOG_FILE, --log-file LOG_FILE
                        Logging file. Overwrites the config.LOG_FILE parameter
  -t, --flow-tracker    Enables flow tracker, which provides only start/stop flow logging information
  -u, --udp-only        Start without using raw socket (only UDP bind socket)

by Antho Balitrand
```

## Deploying the test topology on AWS

![alt text](https://github.com/AnthoBalitrand/geneve-router/blob/main/terraform-files/north_south_basic.png?raw=true)

The topology above can be easily and quickly deployed using the Terraform stack available in terraform-files/north_south_basic.tf

```bash
cd terraform-files
export AWS_ACCESS_KEY_ID = "<your key ID>"
export AWS_SECRET_ACCESS_KEY = "<your secret key>" 
export AWS_DEFAULT_REGION = "eu-west-3" #replace with your favorite region
terraform apply 
```

Extract the generated SSH keys generated to connect to your instances : 

```bash
terraform output -raw private_key > /tmp/geneve-router-lab.key
chmod 600 /tmp/geneve-router-lab.key

ssh -i /tmp/geneve-router-lab.key ec2-user@<intance-public-ip>
```

The Geneve-router is started as a daemon on the inspection instances, without logging enabled. 
Feel free to change the configuration file parameters / restart it to enable logging or start it as an attached process. 

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
