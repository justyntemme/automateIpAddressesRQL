#!/bin/bash

export CLOUD_ACCOUNT="ZOOM-SANDBOX-2"
export VPC_ID="vpc-2345"
export SECURITY_GROUPS="sg-123456,sg-54321"
export CIDR_IPS="192.168.0.1,192.168.0.2"

python main.py
