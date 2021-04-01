from aws_cdk import (core,
                     aws_lambda as lambda_,
                     aws_s3 as s3,
                     aws_lambda_event_sources)

class IntelixLambdaService(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # S3 bucket used for Lambda function code
        lambda_code_bucket = s3.Bucket(self, "IntelixLambda")
        # S3 bucket used by application - this will contain objects to be scanned
        input_bucket = s3.Bucket(self, "IntelixLambdaInput")
        # S3 bucket used by application output - this will contain objects that have been scanned and pass as non-malware
        output_bucket = s3.Bucket(self, "IntelixLambdaOutput")

        # Core Lambda function
        handler = lambda_.Function(self, "IntelixLambdaHandler",
                    runtime=lambda_.Runtime.PYTHON_3_7,
                    code=lambda_.Code.from_asset("resources"),
                    handler="intelix_file_check.file_check_handler",
                    timeout=core.Duration.seconds(900),
                    environment=dict(
                        BUCKET=lambda_code_bucket.bucket_name,
                        INTELIX_CREDENTIALS="<YOUR BASE64 CODED CLIENT_ID:CLIENT_SECRET>",
                        OUTPUT_BUCKET=output_bucket.bucket_name
                    )
                  )
        lambda_code_bucket.grant_read_write(handler)
        input_bucket.grant_read_write(handler)
        output_bucket.grant_read_write(handler)

        # Event Trigger - upon object created in input_bucket call the lambda
        handler.add_event_source(aws_lambda_event_sources.S3EventSource(input_bucket,
            events=[s3.EventType.OBJECT_CREATED]
        ))
