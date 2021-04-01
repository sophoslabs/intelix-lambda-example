#!/usr/bin/env python3

from aws_cdk import core

from cdk_intelix_lambda.intelix_lambda_service import IntelixLambdaService

app = core.App()

IntelixLambdaService(app, "intelix-lambda")

app.synth()
