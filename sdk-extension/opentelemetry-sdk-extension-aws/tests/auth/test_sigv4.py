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

import unittest

# pylint: disable=no-name-in-module
from opentelemetry.sdk.extension.aws.auth.sigv4 import AwsAuthSession
from opentelemetry.sdk.extension.aws.auth.AwsAuthSession import AwsAuthSession as DirectAwsAuthSession


class TestSigV4Module(unittest.TestCase):
    
    def test_import_aws_auth_session(self):
        """Test that AwsAuthSession can be imported from sigv4 module."""
        # Verify that the imported class is the same as the direct import
        self.assertEqual(AwsAuthSession, DirectAwsAuthSession)
    
    def test_aws_auth_session_instantiation(self):
        """Test that AwsAuthSession can be instantiated through sigv4 module."""
        session = AwsAuthSession("us-west-2")
        self.assertEqual(session._aws_region, "us-west-2")
    
    def test_module_all_attribute(self):
        """Test that the sigv4 module exports the expected classes."""
        import opentelemetry.sdk.extension.aws.auth.sigv4 as sigv4_module
        self.assertEqual(sigv4_module.__all__, ["AwsAuthSession"])


if __name__ == '__main__':
    unittest.main()
