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
from unittest.mock import Mock, patch, MagicMock
import requests

# pylint: disable=no-name-in-module
from opentelemetry.sdk.extension.aws.auth.AwsAuthSession import AwsAuthSession, SERVICE_LOGS, SERVICE_XRAY


class TestAwsAuthSession(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.aws_region = "us-west-2"
        self.auth_session = AwsAuthSession(self.aws_region)
    
    def test_init(self):
        """Test AwsAuthSession initialization."""
        session = AwsAuthSession("us-east-1")
        self.assertEqual(session._aws_region, "us-east-1")
        self.assertIsInstance(session, requests.Session)
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.auth.SigV4Auth')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.awsrequest.AWSRequest')
    @patch('requests.Session.request')
    def test_request_with_xray_service(self, mock_super_request, mock_aws_request, mock_sigv4_auth, mock_session):
        """Test request method with X-Ray service URL."""
        # Setup mocks
        mock_credentials = Mock()
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_botocore_session
        
        mock_signer = Mock()
        mock_sigv4_auth.return_value = mock_signer
        
        mock_request = Mock()
        mock_request.headers = {"Authorization": "AWS4-HMAC-SHA256 ...", "X-Amz-Date": "20230101T000000Z"}
        mock_aws_request.return_value = mock_request
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://xray.us-west-2.amazonaws.com/traces"
        data = b"test data"
        
        # Execute
        result = self.auth_session.request(method, url, data=data)
        
        # Verify
        mock_session.assert_called_once()
        mock_botocore_session.get_credentials.assert_called_once()
        mock_sigv4_auth.assert_called_once_with(mock_credentials, SERVICE_XRAY, self.aws_region)
        mock_aws_request.assert_called_once_with(
            method=method,
            url=url,
            data=data,
            headers={"Content-Type": "application/x-protobuf"}
        )
        mock_signer.add_auth.assert_called_once_with(mock_request)
        
        # Verify super().request was called with signed headers
        expected_headers = {
            "Authorization": "AWS4-HMAC-SHA256 ...",
            "X-Amz-Date": "20230101T000000Z"
        }
        mock_super_request.assert_called_once_with(
            method, url, data=data, headers=expected_headers
        )
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.auth.SigV4Auth')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.awsrequest.AWSRequest')
    @patch('requests.Session.request')
    def test_request_with_logs_service(self, mock_super_request, mock_aws_request, mock_sigv4_auth, mock_session):
        """Test request method with CloudWatch Logs service URL."""
        # Setup mocks
        mock_credentials = Mock()
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_botocore_session
        
        mock_signer = Mock()
        mock_sigv4_auth.return_value = mock_signer
        
        mock_request = Mock()
        mock_request.headers = {"Authorization": "AWS4-HMAC-SHA256 ...", "X-Amz-Date": "20230101T000000Z"}
        mock_aws_request.return_value = mock_request
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://logs.us-west-2.amazonaws.com/"
        data = b"test data"
        
        # Execute
        result = self.auth_session.request(method, url, data=data)
        
        # Verify
        mock_sigv4_auth.assert_called_once_with(mock_credentials, SERVICE_LOGS, self.aws_region)
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('requests.Session.request')
    @patch('builtins.print')
    def test_request_with_invalid_service(self, mock_print, mock_super_request, mock_session):
        """Test request method with invalid service URL."""
        # Setup mocks
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = None
        mock_session.return_value = mock_botocore_session
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://invalid-service.amazonaws.com/"
        data = b"test data"
        
        # Execute
        result = self.auth_session.request(method, url, data=data)
        
        # Verify error message was printed
        mock_print.assert_any_call("Error:: invalid service")
        
        # Verify super().request was called without signed headers
        mock_super_request.assert_called_once_with(
            method, url, data=data, headers=None
        )
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('requests.Session.request')
    def test_request_with_no_credentials(self, mock_super_request, mock_session):
        """Test request method when no AWS credentials are available."""
        # Setup mocks
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = None
        mock_session.return_value = mock_botocore_session
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://xray.us-west-2.amazonaws.com/traces"
        data = b"test data"
        
        # Execute
        result = self.auth_session.request(method, url, data=data)
        
        # Verify super().request was called without signed headers
        mock_super_request.assert_called_once_with(
            method, url, data=data, headers=None
        )
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.auth.SigV4Auth')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.awsrequest.AWSRequest')
    @patch('requests.Session.request')
    @patch('builtins.print')
    def test_request_with_signing_error(self, mock_print, mock_super_request, mock_aws_request, mock_sigv4_auth, mock_session):
        """Test request method when signing fails."""
        # Setup mocks
        mock_credentials = Mock()
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_botocore_session
        
        mock_signer = Mock()
        mock_signer.add_auth.side_effect = Exception("Signing failed")
        mock_sigv4_auth.return_value = mock_signer
        
        mock_request = Mock()
        mock_aws_request.return_value = mock_request
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://xray.us-west-2.amazonaws.com/traces"
        data = b"test data"
        
        # Execute
        result = self.auth_session.request(method, url, data=data)
        
        # Verify error was printed
        mock_print.assert_any_call(unittest.mock.ANY)  # The exception object
        
        # Verify super().request was still called
        mock_super_request.assert_called_once()
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.auth.SigV4Auth')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.awsrequest.AWSRequest')
    @patch('requests.Session.request')
    def test_request_with_existing_headers(self, mock_super_request, mock_aws_request, mock_sigv4_auth, mock_session):
        """Test request method with existing headers."""
        # Setup mocks
        mock_credentials = Mock()
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_botocore_session
        
        mock_signer = Mock()
        mock_sigv4_auth.return_value = mock_signer
        
        mock_request = Mock()
        mock_request.headers = {"Authorization": "AWS4-HMAC-SHA256 ...", "X-Amz-Date": "20230101T000000Z"}
        mock_aws_request.return_value = mock_request
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://xray.us-west-2.amazonaws.com/traces"
        data = b"test data"
        existing_headers = {"User-Agent": "test-agent", "Custom-Header": "custom-value"}
        
        # Execute
        result = self.auth_session.request(method, url, data=data, headers=existing_headers)
        
        # Verify super().request was called with merged headers
        expected_headers = {
            "User-Agent": "test-agent",
            "Custom-Header": "custom-value",
            "Authorization": "AWS4-HMAC-SHA256 ...",
            "X-Amz-Date": "20230101T000000Z"
        }
        mock_super_request.assert_called_once_with(
            method, url, data=data, headers=expected_headers
        )
    
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.session.Session')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.auth.SigV4Auth')
    @patch('opentelemetry.sdk.extension.aws.auth.AwsAuthSession.awsrequest.AWSRequest')
    @patch('requests.Session.request')
    def test_request_with_kwargs(self, mock_super_request, mock_aws_request, mock_sigv4_auth, mock_session):
        """Test request method with additional keyword arguments."""
        # Setup mocks
        mock_credentials = Mock()
        mock_botocore_session = Mock()
        mock_botocore_session.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_botocore_session
        
        mock_signer = Mock()
        mock_sigv4_auth.return_value = mock_signer
        
        mock_request = Mock()
        mock_request.headers = {"Authorization": "AWS4-HMAC-SHA256 ..."}
        mock_aws_request.return_value = mock_request
        
        mock_super_request.return_value = Mock()
        
        # Test data
        method = "POST"
        url = "https://xray.us-west-2.amazonaws.com/traces"
        data = b"test data"
        timeout = 30
        verify = True
        
        # Execute
        result = self.auth_session.request(method, url, data=data, timeout=timeout, verify=verify)
        
        # Verify super().request was called with all arguments
        mock_super_request.assert_called_once_with(
            method, url, data=data, headers={"Authorization": "AWS4-HMAC-SHA256 ..."}, 
            timeout=timeout, verify=verify
        )
    
    @patch('requests.Session.close')
    def test_close(self, mock_super_close):
        """Test close method."""
        # Execute
        self.auth_session.close()
        
        # Verify
        mock_super_close.assert_called_once()
    
    def test_service_constants(self):
        """Test service constants are defined correctly."""
        self.assertEqual(SERVICE_LOGS, "logs")
        self.assertEqual(SERVICE_XRAY, "xray")


if __name__ == '__main__':
    unittest.main()
