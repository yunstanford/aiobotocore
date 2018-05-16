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
from botocore.exceptions import MetadataRetrievalError


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
    return asynctest.mock.Mock(aiohttp.ClientSession)


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


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_retrieve_uri(container_metadata_fetcher, mock_http):
    json_body =  {
        "AccessKeyId" : "a",
        "SecretAccessKey" : "b",
        "Token" : "c",
        "Expiration" : "d"
    }
    mock_http.get = asynctest.CoroutineMock(return_value=MockResponse(200, json.dumps(json_body)))

    response = await container_metadata_fetcher.retrieve_uri('/foo?id=1')

    assert response == json_body
    # Ensure we made calls to the right endpoint.
    mock_http.get.assert_called_with(
        'http://169.254.170.2/foo?id=1',
        headers={'Accept': 'application/json'},
        timeout=container_metadata_fetcher.TIMEOUT_SECONDS,
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_retry_requests(container_metadata_fetcher, mock_http):
    success_response = {
        "AccessKeyId" : "a",
        "SecretAccessKey" : "b",
        "Token" : "c",
        "Expiration" : "d"
    }
    mock_http.get = asynctest.CoroutineMock(
        side_effect=[
            # First response is a connection error, should
            # be retried.
            aiohttp.ClientConnectionError(),
            # Second response is the successful JSON response
            # with credentials.
            MockResponse(200, json.dumps(success_response)),
        ]
    )
    response = await container_metadata_fetcher.retrieve_uri('/foo?id=1')
    assert response == success_response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_propagates_credential_error_on_http_errors(container_metadata_fetcher, mock_http):
    mock_http.get = asynctest.CoroutineMock(
        side_effect=[
            # In this scenario, we never get a successful response.
            aiohttp.ClientConnectionError(),
            aiohttp.ClientConnectionError(),
            aiohttp.ClientConnectionError(),
            aiohttp.ClientConnectionError(),
            aiohttp.ClientConnectionError(),
        ]
    )
    # As a result, we expect an appropriate error to be raised.
    with pytest.raises(MetadataRetrievalError):
        await container_metadata_fetcher.retrieve_uri('/foo?id=1')
    assert mock_http.get.call_count == container_metadata_fetcher.RETRY_ATTEMPTS


@pytest.mark.moto
@pytest.mark.asyncio
async def test_error_raised_on_non_200_response(container_metadata_fetcher, mock_http):
    mock_http.get = asynctest.CoroutineMock(side_effect=[
        MockResponse(404, text='Error not found'),
        MockResponse(404, text='Error not found'),
        MockResponse(404, text='Error not found'),
    ])
    with pytest.raises(MetadataRetrievalError):
        await container_metadata_fetcher.retrieve_uri('/foo?id=1')
    # Should have tried up to RETRY_ATTEMPTS.
    assert mock_http.get.call_count == container_metadata_fetcher.RETRY_ATTEMPTS


@pytest.mark.moto
@pytest.mark.asyncio
async def test_error_raised_on_no_json_response(container_metadata_fetcher, mock_http):
    # If the service returns a sucess response but with a body that
    # does not contain JSON, we should still retry up to RETRY_ATTEMPTS,
    # but after exhausting retries we propagate the exception.
    mock_http.get = asynctest.CoroutineMock(side_effect=[
        MockResponse(404, text='Not JSON'),
        MockResponse(404, text='Not JSON'),
        MockResponse(404, text='Not JSON'),
    ])
    with pytest.raises(MetadataRetrievalError):
        await container_metadata_fetcher.retrieve_uri('/foo?id=1')
    # Should have tried up to RETRY_ATTEMPTS.
    assert mock_http.get.call_count == container_metadata_fetcher.RETRY_ATTEMPTS


async def _assert_can_retrieve_metadata_from(full_uri, mock_http, container_metadata_fetcher):
    response_body = {'foo': 'bar'}
    mock_http.get = asynctest.CoroutineMock(return_value=MockResponse(200, json.dumps(response_body)))
    response = await container_metadata_fetcher.retrieve_full_uri(full_uri)
    assert response == response_body
    mock_http.get.assert_called_with(
        full_uri, headers={'Accept': 'application/json'},
        timeout=container_metadata_fetcher.TIMEOUT_SECONDS,
    )


async def _assert_host_is_not_allowed(full_uri, container_metadata_fetcher, mock_http):
    response_body = {'foo': 'bar'}
    mock_http.get = asynctest.CoroutineMock(return_value=MockResponse(200, json.dumps(response_body)))
    with pytest.raises(ValueError) as e:
        await container_metadata_fetcher.retrieve_full_uri(full_uri)
        assert str(e) == 'Unsupported host'
    assert mock_http.get.called is False


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_retrieve_full_uri_with_fixed_ip(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from(
        'http://%s/foo?id=1' % ContainerMetadataFetcher.IP_ADDRESS, mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_localhost_http_is_allowed(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from('http://localhost/foo', mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_localhost_with_port_http_is_allowed(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from('http://localhost:8000/foo', mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_localhost_https_is_allowed(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from('https://localhost/foo', mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_use_127_ip_addr(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from('https://127.0.0.1/foo', mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_use_127_ip_addr_with_port(container_metadata_fetcher, mock_http):
    await _assert_can_retrieve_metadata_from('https://127.0.0.1:8080/foo', mock_http, container_metadata_fetcher)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_link_local_http_is_not_allowed(container_metadata_fetcher, mock_http):
    await _assert_host_is_not_allowed('http://169.254.0.1/foo', container_metadata_fetcher, mock_http)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_link_local_https_is_not_allowed(container_metadata_fetcher, mock_http):
    await _assert_host_is_not_allowed('https://169.254.0.1/foo', container_metadata_fetcher, mock_http)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_non_link_local_nonallowed_url(container_metadata_fetcher, mock_http):
    await _assert_host_is_not_allowed('http://169.1.2.3/foo', container_metadata_fetcher, mock_http)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_error_raised_on_nonallowed_url(container_metadata_fetcher, mock_http):
    await _assert_host_is_not_allowed('http://somewhere.com/foo', container_metadata_fetcher, mock_http)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_external_host_not_allowed_if_https(container_metadata_fetcher, mock_http):
    await _assert_host_is_not_allowed('https://somewhere.com/foo', container_metadata_fetcher, mock_http)
