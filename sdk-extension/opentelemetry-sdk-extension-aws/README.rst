OpenTelemetry SDK Extension for AWS X-Ray Compatibility
=======================================================

|pypi|

.. |pypi| image:: https://badge.fury.io/py/opentelemetry-sdk-extension-aws.svg
   :target: https://pypi.org/project/opentelemetry-sdk-extension-aws/


This library provides components necessary to configure the OpenTelemetry SDK
for tracing with AWS X-Ray.

Installation
------------

::

    pip install opentelemetry-sdk-extension-aws


Usage (AWS X-Ray IDs Generator)
-------------------------------

Configure the OTel SDK TracerProvider with the provided custom IDs Generator to 
make spans compatible with the AWS X-Ray backend tracing service.

Install the OpenTelemetry SDK package.

::

    pip install opentelemetry-sdk

Next, use the provided `AwsXRayIdGenerator` to initialize the `TracerProvider`.

.. code-block:: python

    import opentelemetry.trace as trace
    from opentelemetry.sdk.extension.aws.trace import AwsXRayIdGenerator
    from opentelemetry.sdk.trace import TracerProvider

    trace.set_tracer_provider(
        TracerProvider(id_generator=AwsXRayIdGenerator())
    )


Usage (AWS Resource Detectors)
------------------------------

Use the provided `Resource Detectors` to automatically populate attributes under the `resource`
namespace of each generated span.

For example, if tracing with OpenTelemetry on an AWS EC2 instance, you can automatically
populate `resource` attributes by creating a `TraceProvider` using the `AwsEc2ResourceDetector`:

.. code-block:: python

    import opentelemetry.trace as trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.extension.aws.resource.ec2 import (
        AwsEc2ResourceDetector,
    )
    from opentelemetry.sdk.resources import get_aggregated_resources

    trace.set_tracer_provider(
        TracerProvider(
            resource=get_aggregated_resources(
                [
                    AwsEc2ResourceDetector(),
                ]
            ),
        )
    )

Refer to each detectors' docstring to determine any possible requirements for that
detector.

Usage (AWS Authentication for OTLP Exports)
-------------------------------------------

Use the provided `AwsAuthSession` to authenticate OTLP exports to AWS X-Ray and CloudWatch Logs OTLP endpoints using AWS Signature Version 4 (SigV4) authentication.

Requirements
~~~~~~~~~~~~

To use the AWS authentication session, you need to install the required dependencies:

::

    pip install botocore requests

Usage Example
~~~~~~~~~~~~~

The `AwsAuthSession` can be used with both span and logs OTLP exporters by passing it as the `session` parameter:

.. code-block:: python

    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.http.logs_exporter import OTLPLogExporter
    from opentelemetry.sdk.extension.aws.auth.aws_auth_session import AwsAuthSession

    # Initialize the AWS authentication session
    aws_session = AwsAuthSession(aws_region="us-west-2")

    # Configure OTLP span exporter for AWS X-Ray
    span_exporter = OTLPSpanExporter(
        endpoint="https://xray.us-west-2.amazonaws.com/traces",
        session=aws_session
    )

    # Configure OTLP logs exporter for CloudWatch Logs
    logs_exporter = OTLPLogExporter(
        endpoint="https://logs.us-west-2.amazonaws.com/",
        session=aws_session
    )

AWS Credentials Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `AwsAuthSession` uses the AWS SDK (botocore) for retrieving user credentials and authenticating export requests. Therefore, the session follows the AWS SDK's credential resolution chain.

**Setting AWS Credentials**

You can provide AWS credentials using any of the following methods:

1. **Environment Variables:**

   .. code-block:: bash

       export AWS_ACCESS_KEY_ID=your_access_key_id
       export AWS_SECRET_ACCESS_KEY=your_secret_access_key
       export AWS_SESSION_TOKEN=your_session_token  # Optional, for temporary credentials

2. **AWS Credentials File:**

   Create or update ``~/.aws/credentials``:

   .. code-block:: ini

       [default]
       aws_access_key_id = your_access_key_id
       aws_secret_access_key = your_secret_access_key

3. **AWS Config File:**

   Create or update ``~/.aws/config``:

   .. code-block:: ini

       [default]
       region = us-west-2

4. **IAM Roles (for EC2, ECS, Lambda, etc.):**

   When running on AWS services, the session will automatically use the IAM role attached to the service. No additional configuration is required.

**Using IAM Roles**

For applications running on AWS infrastructure, you can use IAM roles instead of hardcoded credentials:

- **EC2 Instances:** Attach an IAM role to your EC2 instance
- **ECS Tasks:** Assign a task role to your ECS task definition  
- **Lambda Functions:** Configure an execution role for your Lambda function
- **EKS Pods:** Use IAM roles for service accounts (IRSA)

The `AwsAuthSession` will automatically detect and use these roles without requiring any code changes.

References
----------

* `OpenTelemetry Project <https://opentelemetry.io/>`_
* `AWS X-Ray Trace IDs Format <https://docs.aws.amazon.com/xray/latest/devguide/xray-api-sendingdata.html#xray-api-traceids>`_
* `OpenTelemetry Specification for Resource Attributes <https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/resource/semantic_conventions>`_
* `AWS SDK Credential Resolution <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html>`_
