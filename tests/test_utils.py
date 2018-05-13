# Copyright 2012-2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import aiohttp
import asynctest
import asyncio
import json
import pytest

from aiobotocore.utils import ContainerMetadataFetcher


class MockResponse(object):

    def __init__(self, status, text):
        self._status = status
        self._text = text

    @property
    def status(self):
        return self._status

    async def text(self):
        return self._text

@pytest.fixture
def mock_http():
    return asynctest.mock.Mock(aiohttp.ClientSession())


@pytest.fixture
def container_metadata_fetcher(mock_http):
    return ContainerMetadataFetcher(mock_http)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_specify_extra_headers_are_merged(container_metadata_fetcher, mock_http):
    headers = {
        # The 'Accept' header will override the
        # default Accept header of application/json.
        'Accept': 'application/not-json',
        'X-Other-Header': 'foo',
    }
    mock_http.get = asynctest.CoroutineMock(return_value=MockResponse(200, json.dumps({'foo': 'bar'})))
    response = await container_metadata_fetcher.retrieve_full_uri(
        'http://localhost', headers)
    mock_http.get.assert_called_with(
        'http://localhost', headers=headers,
        timeout=container_metadata_fetcher.TIMEOUT_SECONDS,
    )



# class TestContainerMetadataFetcher(unittest.TestCase):
#     def setUp(self):
#         self.responses = []
#         self.http = mock.Mock()
#         self.sleep = mock.Mock()

#     def create_fetcher(self):
#         return ContainerMetadataFetcher(self.http, sleep=self.sleep)

#     def fake_response(self, status_code, body):
#         response = mock.Mock()
#         response.status_code = status_code
#         response.text = body
#         return response

#     def set_http_responses_to(self, *responses):
#         http_responses = []
#         for response in responses:
#             if isinstance(response, Exception):
#                 # Simulating an error condition.
#                 http_response = response
#             elif hasattr(response, 'status_code'):
#                 # It's a precreated fake_response.
#                 http_response = response
#             else:
#                 http_response = self.fake_response(
#                     status_code=200, body=json.dumps(response))
#             http_responses.append(http_response)
#         self.http.get.side_effect = http_responses

#     def assert_can_retrieve_metadata_from(self, full_uri):
#         response_body = {'foo': 'bar'}
#         self.set_http_responses_to(response_body)
#         fetcher = self.create_fetcher()
#         response = fetcher.retrieve_full_uri(full_uri)
#         self.assertEqual(response, response_body)
#         self.http.get.assert_called_with(
#             full_uri, headers={'Accept': 'application/json'},
#             timeout=fetcher.TIMEOUT_SECONDS,
#         )

#     def assert_host_is_not_allowed(self, full_uri):
#         response_body = {'foo': 'bar'}
#         self.set_http_responses_to(response_body)
#         fetcher = self.create_fetcher()
#         with self.assertRaisesRegexp(ValueError, 'Unsupported host'):
#             fetcher.retrieve_full_uri(full_uri)
#         self.assertFalse(self.http.get.called)

#     def test_can_specify_extra_headers_are_merged(self):
#         headers = {
#             # The 'Accept' header will override the
#             # default Accept header of application/json.
#             'Accept': 'application/not-json',
#             'X-Other-Header': 'foo',
#         }
#         self.set_http_responses_to({'foo': 'bar'})
#         fetcher = self.create_fetcher()
#         response = fetcher.retrieve_full_uri(
#             'http://localhost', headers)
#         self.http.get.assert_called_with(
#             'http://localhost', headers=headers,
#             timeout=fetcher.TIMEOUT_SECONDS,
#         )

#     def test_can_retrieve_uri(self):
#         json_body =  {
#             "AccessKeyId" : "a",
#             "SecretAccessKey" : "b",
#             "Token" : "c",
#             "Expiration" : "d"
#         }
#         self.set_http_responses_to(json_body)

#         fetcher = self.create_fetcher()
#         response = fetcher.retrieve_uri('/foo?id=1')

#         self.assertEqual(response, json_body)
#         # Ensure we made calls to the right endpoint.
#         self.http.get.assert_called_with(
#             'http://169.254.170.2/foo?id=1',
#             headers={'Accept': 'application/json'},
#             timeout=fetcher.TIMEOUT_SECONDS,
#         )

#     def test_can_retry_requests(self):
#         success_response = {
#             "AccessKeyId" : "a",
#             "SecretAccessKey" : "b",
#             "Token" : "c",
#             "Expiration" : "d"
#         }
#         self.set_http_responses_to(
#             # First response is a connection error, should
#             # be retried.
#             requests.ConnectionError(),
#             # Second response is the successful JSON response
#             # with credentials.
#             success_response,
#         )
#         fetcher = self.create_fetcher()
#         response = fetcher.retrieve_uri('/foo?id=1')
#         self.assertEqual(response, success_response)

#     def test_propagates_credential_error_on_http_errors(self):
#         self.set_http_responses_to(
#             # In this scenario, we never get a successful response.
#             requests.ConnectionError(),
#             requests.ConnectionError(),
#             requests.ConnectionError(),
#             requests.ConnectionError(),
#             requests.ConnectionError(),
#         )
#         # As a result, we expect an appropriate error to be raised.
#         fetcher = self.create_fetcher()
#         with self.assertRaises(MetadataRetrievalError):
#             fetcher.retrieve_uri('/foo?id=1')
#         self.assertEqual(self.http.get.call_count, fetcher.RETRY_ATTEMPTS)

#     def test_error_raised_on_non_200_response(self):
#         self.set_http_responses_to(
#             self.fake_response(status_code=404, body='Error not found'),
#             self.fake_response(status_code=404, body='Error not found'),
#             self.fake_response(status_code=404, body='Error not found'),
#         )
#         fetcher = self.create_fetcher()
#         with self.assertRaises(MetadataRetrievalError):
#             fetcher.retrieve_uri('/foo?id=1')
#         # Should have tried up to RETRY_ATTEMPTS.
#         self.assertEqual(self.http.get.call_count, fetcher.RETRY_ATTEMPTS)

#     def test_error_raised_on_no_json_response(self):
#         # If the service returns a sucess response but with a body that
#         # does not contain JSON, we should still retry up to RETRY_ATTEMPTS,
#         # but after exhausting retries we propagate the exception.
#         self.set_http_responses_to(
#             self.fake_response(status_code=200, body='Not JSON'),
#             self.fake_response(status_code=200, body='Not JSON'),
#             self.fake_response(status_code=200, body='Not JSON'),
#         )
#         fetcher = self.create_fetcher()
#         with self.assertRaises(MetadataRetrievalError):
#             fetcher.retrieve_uri('/foo?id=1')
#         # Should have tried up to RETRY_ATTEMPTS.
#         self.assertEqual(self.http.get.call_count, fetcher.RETRY_ATTEMPTS)

#     def test_can_retrieve_full_uri_with_fixed_ip(self):
#         self.assert_can_retrieve_metadata_from(
#             'http://%s/foo?id=1' % ContainerMetadataFetcher.IP_ADDRESS)

#     def test_localhost_http_is_allowed(self):
#         self.assert_can_retrieve_metadata_from('http://localhost/foo')

#     def test_localhost_with_port_http_is_allowed(self):
#         self.assert_can_retrieve_metadata_from('http://localhost:8000/foo')

#     def test_localhost_https_is_allowed(self):
#         self.assert_can_retrieve_metadata_from('https://localhost/foo')

#     def test_can_use_127_ip_addr(self):
#         self.assert_can_retrieve_metadata_from('https://127.0.0.1/foo')

#     def test_can_use_127_ip_addr_with_port(self):
#         self.assert_can_retrieve_metadata_from('https://127.0.0.1:8080/foo')

#     def test_link_local_http_is_not_allowed(self):
#         self.assert_host_is_not_allowed('http://169.254.0.1/foo')

#     def test_link_local_https_is_not_allowed(self):
#         self.assert_host_is_not_allowed('https://169.254.0.1/foo')

#     def test_non_link_local_nonallowed_url(self):
#         self.assert_host_is_not_allowed('http://169.1.2.3/foo')

#     def test_error_raised_on_nonallowed_url(self):
#         self.assert_host_is_not_allowed('http://somewhere.com/foo')

#     def test_external_host_not_allowed_if_https(self):
#         self.assert_host_is_not_allowed('https://somewhere.com/foo')
