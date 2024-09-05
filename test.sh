#!/bin/bash

export cloudAccount="ZOOM-SANDBOX-2"
export vpcId="vpc-2345"
export securityGroups="sg-123456,sg-54321"
export cidrIps="192.168.0.1,192.168.0.2"

python main.py
