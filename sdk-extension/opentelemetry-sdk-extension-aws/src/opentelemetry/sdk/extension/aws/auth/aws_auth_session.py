# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint:disable=no-name-in-module

import requests
from botocore import session, auth, awsrequest

SERVICE_LOGS = "logs"
SERVICE_XRAY = "xray"


class AwsAuthSession(requests.Session):

    def __init__(self, aws_region):
        self._aws_region = aws_region
        self.botocore_session = session.Session()

        super().__init__()

    def request(
            self,
            method,
            url,
            data=None,
            headers=None,
            *args,
            **kwargs
    ):
        print("In AwsAuthSession.request")

        service = None
        if "xray" in url:
            service = SERVICE_XRAY
        elif "logs" in url:
            service = SERVICE_LOGS
        else:
            print("Error:: invalid service")

        credentials = self.botocore_session.get_credentials()

        if credentials is not None:
            signer = auth.SigV4Auth(credentials, service, self._aws_region)

            request = awsrequest.AWSRequest(
                method=method,
                url=url,
                data=data,
                headers={"Content-Type": "application/x-protobuf"},
            )

            try:
                signer.add_auth(request)
                print("request.headers: ", request.headers)

                # update headers
                if headers is None:
                    headers = {}
                for key, value in request.headers.items():
                    headers[key] = value


            except Exception as signing_error:  # pylint: disable=broad-except
                print(signing_error)
                # _logger.error("Failed to sign request: %s", signing_error)

        return super().request(method, url, data=data, headers=headers, *args, **kwargs)

    def close(self):
        super().close()
