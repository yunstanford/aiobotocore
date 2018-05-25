# Copyright (c) 2012-2013 Mitch Garnaat http://garnaat.org/
# Copyright 2012-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
from datetime import datetime, timedelta
from asyncio import subprocess
import asyncio
import mock
import os
import tempfile
import shutil
import json
import copy
import pytest
import asynctest
from dateutil.tz import tzlocal, tzutc

import aiobotocore.session
from aiobotocore import credentials
from aiobotocore.utils import ContainerMetadataFetcher
from aiobotocore.credentials import EnvProvider, create_assume_role_refresher
from aiobotocore.credentials import CredentialProvider, AssumeRoleProvider
from aiobotocore.credentials import ConfigProvider, SharedCredentialProvider
from aiobotocore.credentials import Credentials
import botocore
import botocore.exceptions
from botocore.compat import json
from botocore import utils


# Passed to session to keep it from finding default config file
TESTENVVARS = {'config_file': (None, 'AWS_CONFIG_FILE', None)}


raw_metadata = {
    'foobar': {
        'Code': 'Success',
        'LastUpdated': '2012-12-03T14:38:21Z',
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'Token': 'foobar',
        'Expiration': '2012-12-03T20:48:03Z',
        'Type': 'AWS-HMAC'
    }
}
post_processed_metadata = {
    'role_name': 'foobar',
    'access_key': raw_metadata['foobar']['AccessKeyId'],
    'secret_key': raw_metadata['foobar']['SecretAccessKey'],
    'token': raw_metadata['foobar']['Token'],
    'expiry_time': raw_metadata['foobar']['Expiration'],
}


def path(filename):
    return os.path.join(os.path.dirname(__file__), 'cfg', filename)


#########################
# class TestCredentials #
#########################
@pytest.mark.moto
def test_credentials_detect_nonascii_character():
    c = credentials.Credentials('foo\xe2\x80\x99', 'bar\xe2\x80\x99')
    assert isinstance(c.access_key, type(u'u')) is True
    assert isinstance(c.secret_key, type(u'u')) is True


@pytest.mark.moto
def test_credentials_unicode_input():
    c = credentials.Credentials(u'foo', u'bar')
    assert isinstance(c.access_key, type(u'u')) is True
    assert isinstance(c.secret_key, type(u'u')) is True


####################################
# class TestRefreshableCredentials #
####################################
@pytest.fixture
def mock_time():
    return mock.Mock()


@pytest.fixture
def refreshable_credentials(mock_time):
    future_time = datetime.now(tzlocal()) + timedelta(hours=24)
    expiry_time = datetime.now(tzlocal()) - timedelta(minutes=30)
    metadata = {
        'access_key': 'NEW-ACCESS',
        'secret_key': 'NEW-SECRET',
        'token': 'NEW-TOKEN',
        'expiry_time': future_time.isoformat(),
        'role_name': 'rolename',
    }
    refresher = asynctest.CoroutineMock(return_value=metadata)
    return credentials.RefreshableCredentials(
        'ORIGINAL-ACCESS', 'ORIGINAL-SECRET', 'ORIGINAL-TOKEN',
        expiry_time, refresher, 'iam-role',
        time_fetcher=mock_time,
    )


@pytest.mark.moto
def test_refreshable_credentials_refresh_needed(mock_time, refreshable_credentials):
    # The expiry time was set for 30 minutes ago, so if we
    # say the current time is utcnow(), then we should need
    # a refresh.
    mock_time.return_value = datetime.now(tzlocal())
    assert refreshable_credentials.refresh_needed() is True


@pytest.mark.moto
def test_refreshable_credentials_no_expiration(mock_time):
    creds = credentials.RefreshableCredentials(
        'ORIGINAL-ACCESS', 'ORIGINAL-SECRET', 'ORIGINAL-TOKEN',
        None, mock.Mock(), 'iam-role', time_fetcher=mock_time
    )
    assert creds.refresh_needed() is False


@pytest.mark.moto
def test_refreshable_credentials_no_refresh_needed(mock_time, refreshable_credentials):
    # The expiry time was 30 minutes ago, let's say it's an hour
    # ago currently.  That would mean we don't need a refresh.
    mock_time.return_value = (
        datetime.now(tzlocal()) - timedelta(minutes=60))
    assert refreshable_credentials.refresh_needed() is False


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshable_credentials_get_credentials_set(mock_time, refreshable_credentials):
    # We need to return a consistent set of credentials to use during the
    # signing process.
    mock_time.return_value = (
        datetime.now(tzlocal()) - timedelta(minutes=60))
    assert refreshable_credentials.refresh_needed() is False
    credential_set = await refreshable_credentials.get_frozen_credentials()
    assert credential_set.access_key == 'ORIGINAL-ACCESS'
    assert credential_set.secret_key == 'ORIGINAL-SECRET'
    assert credential_set.token == 'ORIGINAL-TOKEN'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshable_credentials__refresh(mock_time, refreshable_credentials):
    # The expiry time was set for 30 minutes ago, so if we
    # say the current time is utcnow(), then we should need
    # a refresh.
    mock_time.return_value = datetime.now(tzlocal())
    await refreshable_credentials._refresh()
    assert refreshable_credentials.access_key == 'NEW-ACCESS'
    assert refreshable_credentials.secret_key == 'NEW-SECRET'
    assert refreshable_credentials.token == 'NEW-TOKEN'


############################################
# class TestDeferredRefreshableCredentials #
############################################
@pytest.fixture
def refresher():
    future_time = datetime.now(tzlocal()) + timedelta(hours=24)
    metadata = {
        'access_key': 'NEW-ACCESS',
        'secret_key': 'NEW-SECRET',
        'token': 'NEW-TOKEN',
        'expiry_time': future_time.isoformat(),
        'role_name': 'rolename',
    }
    return asynctest.CoroutineMock(return_value=metadata)


@pytest.fixture
def deferred_refreshable_credentials(refresher, mock_time):
    mock_time.return_value = datetime.now(tzlocal())
    return credentials.DeferredRefreshableCredentials(
            refresher, 'iam-role', mock_time,
        )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_deferred_refreshable_credentials_refresh_using_called_on_first_access(
        deferred_refreshable_credentials, refresher):
    assert refresher.called is False
    await deferred_refreshable_credentials.get_frozen_credentials()
    assert refresher.call_count == 1


#########################################
# class TestAssumeRoleCredentialFetcher #
#########################################
def get_expected_creds_from_response(response):
    expiration = response['Credentials']['Expiration']
    if isinstance(expiration, datetime):
        expiration = expiration.isoformat()
    return {
        'access_key': response['Credentials']['AccessKeyId'],
        'secret_key': response['Credentials']['SecretAccessKey'],
        'token': response['Credentials']['SessionToken'],
        'expiry_time': expiration
    }


def some_future_time():
    timeobj = datetime.now(tzlocal())
    return timeobj + timedelta(hours=24)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_credential_fetcher_no_cache():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn
    )

    expected_response = get_expected_creds_from_response(response)
    response = await refresher.fetch_credentials()

    assert response == expected_response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_credential_fetcher_expiration_in_datetime_format():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # Note the lack of isoformat(), we're using
            # a datetime.datetime type.  This will ensure
            # we test both parsing as well as serializing
            # from a given datetime because the credentials
            # are immediately expired.
            'Expiration': some_future_time(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn
    )

    expected_response = get_expected_creds_from_response(response)
    response = await refresher.fetch_credentials()

    assert response == expected_response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_credential_fetcher_retrieves_from_cache():
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'
    cache_key = (
        '793d6e2f27667ab2da104824407e486bfec24a47'
    )
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            }
        }
    }

    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn, cache=cache,
    )

    expected_response = get_expected_creds_from_response(
        cache[cache_key]
    )
    response = await refresher.fetch_credentials()

    assert response == expected_response
    client_creator.assert_not_called()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_credential_fetcher_cache_key_is_windows_safe():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    cache = {}

    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'arn:aws:iam::role/foo-role'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn, cache=cache,
    )

    await refresher.fetch_credentials()

    # On windows, you cannot use a a ':' in the filename, so
    # we need to make sure that it doesn't make it into the cache key.
    cache_key = (
        '75c539f0711ba78c5b9e488d0add95f178a54d74'
    )
    assert cache_key in cache
    assert cache[cache_key] == response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_cache_key_with_role_session_name():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    cache = {}
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    role_session_name = 'my_session_name'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn, cache=cache,
        extra_args={'RoleSessionName': role_session_name}
    )
    await refresher.fetch_credentials()

    # This is the sha256 hex digest of the expected assume role args.
    cache_key = (
        '2964201f5648c8be5b9460a9cf842d73a266daf2'
    )
    assert cache_key in cache
    assert cache[cache_key] == response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_cache_key_with_policy():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    cache = {}
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    })

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn, cache=cache,
        extra_args={'Policy': policy}
    )
    await refresher.fetch_credentials()

    # This is the sha256 hex digest of the expected assume role args.
    cache_key = (
        '176f223d915e82456c253545e192aa21d68f5ab8'
    )
    assert cache_key in cache
    assert cache[cache_key] == response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_in_cache_but_expired():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    cache = {
        'development--myrole': {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': datetime.now(tzlocal()),
            }
        }
    }

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn, cache=cache
    )
    expected = get_expected_creds_from_response(response)
    response = await refresher.fetch_credentials()

    assert response == expected


@pytest.mark.moto
@pytest.mark.asyncio
async def test_role_session_name_can_be_provided():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    role_session_name = 'myname'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'RoleSessionName': role_session_name}
    )
    await refresher.fetch_credentials()

    client.assume_role.assert_called_with(
        RoleArn=role_arn, RoleSessionName=role_session_name)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_external_id_can_be_provided():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    external_id = 'my_external_id'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'ExternalId': external_id}
    )
    await refresher.fetch_credentials()

    client.assume_role.assert_called_with(
        RoleArn=role_arn, ExternalId=external_id,
        RoleSessionName=mock.ANY)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_policy_can_be_provided():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    })

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'Policy': policy}
    )
    await refresher.fetch_credentials()

    client.assume_role.assert_called_with(
        RoleArn=role_arn, Policy=policy,
        RoleSessionName=mock.ANY)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_duration_seconds_can_be_provided():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    duration = 1234

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'DurationSeconds': duration}
    )
    await refresher.fetch_credentials()

    client.assume_role.assert_called_with(
        RoleArn=role_arn, DurationSeconds=duration,
        RoleSessionName=mock.ANY)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_mfa():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(return_value=response)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'
    prompter = mock.Mock(return_value='token-code')
    mfa_serial = 'mfa'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'SerialNumber': mfa_serial}, mfa_prompter=prompter
    )
    await refresher.fetch_credentials()

    # In addition to the normal assume role args, we should also
    # inject the serial number from the config as well as the
    # token code that comes from prompting the user (the prompter
    # object).
    client.assume_role.assert_called_with(
        RoleArn='myrole', RoleSessionName=mock.ANY, SerialNumber='mfa',
        TokenCode='token-code')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshes():
    responses = [{
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # We're creating an expiry time in the past so as
            # soon as we try to access the credentials, the
            # refresh behavior will be triggered.
            'Expiration': (
                datetime.now(tzlocal()) -
                timedelta(seconds=100)).isoformat(),
        },
    }, {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        }
    }]
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(side_effect=responses)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn
    )

    # The first call will simply use whatever credentials it is given.
    # The second will check the cache, and only make a call if the
    # cached credentials are expired.
    await refresher.fetch_credentials()
    await refresher.fetch_credentials()

    assume_role_calls = client.assume_role.call_args_list
    assert len(assume_role_calls) == 2


@pytest.mark.moto
@pytest.mark.asyncio
async def test_mfa_refresh_enabled():
    responses = [{
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # We're creating an expiry time in the past so as
            # soon as we try to access the credentials, the
            # refresh behavior will be triggered.
            'Expiration': (
                datetime.now(tzlocal()) -
                timedelta(seconds=100)).isoformat(),
        },
    }, {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        }
    }]
    client = mock.Mock()
    client_creator = mock.Mock(return_value=client)
    client.assume_role = asynctest.CoroutineMock(side_effect=responses)
    source_creds = credentials.Credentials('a', 'b', 'c')
    role_arn = 'myrole'

    token_code = 'token-code-1'
    prompter = mock.Mock(side_effect=[token_code])
    mfa_serial = 'mfa'

    refresher = credentials.AssumeRoleCredentialFetcher(
        client_creator, source_creds, role_arn,
        extra_args={'SerialNumber': mfa_serial}, mfa_prompter=prompter
    )

    # This is will refresh credentials if they're expired. Because
    # we set the expiry time to something in the past, this will
    # trigger the refresh behavior.
    await refresher.fetch_credentials()

    calls = [c[1] for c in client.assume_role.call_args_list]
    expected_calls = [
        {
            'RoleArn': role_arn,
            'RoleSessionName': mock.ANY,
            'SerialNumber': mfa_serial,
            'TokenCode': token_code
        }
    ]
    assert calls == expected_calls


####################
# class TestEnvVar #
####################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_envvars_are_found_no_token():
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.method == 'env'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_envvars_found_with_security_token():
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SECURITY_TOKEN': 'baz',
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()

    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.method == 'env'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_envvars_found_with_session_token():
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()
    
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.method == 'env'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_envvars_not_found():
    provider = credentials.EnvProvider(environ={})
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_override_env_var_mapping():
    # We can change the env var provider to
    # use our specified env var names.
    environ = {
        'FOO_ACCESS_KEY': 'foo',
        'FOO_SECRET_KEY': 'bar',
        'FOO_SESSION_TOKEN': 'baz',
    }
    mapping = {
        'access_key': 'FOO_ACCESS_KEY',
        'secret_key': 'FOO_SECRET_KEY',
        'token': 'FOO_SESSION_TOKEN',
    }
    provider = credentials.EnvProvider(
        environ, mapping
    )
    creds = await provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_override_partial_env_var_mapping():
    # Only changing the access key mapping.
    # The other 2 use the default values of
    # AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN
    # use our specified env var names.
    environ = {
        'FOO_ACCESS_KEY': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
    }
    provider = credentials.EnvProvider(
        environ, {'access_key': 'FOO_ACCESS_KEY'}
    )
    creds = await provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_override_expiry_env_var_mapping():
    expiry_time = datetime.now(tzlocal()) - timedelta(hours=1)
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
        'FOO_EXPIRY': expiry_time.isoformat(),
    }
    provider = credentials.EnvProvider(
        environ, {'expiry_time': 'FOO_EXPIRY'}
    )
    creds = await provider.load()

    # Since the credentials are expired, we'll trigger a refresh whenever
    # we try to access them. Since the environment credentials are still
    # expired, this will raise an error.
    error_message = (
        "Credentials were refreshed, but the refreshed credentials are "
        "still expired."
    )
    with pytest.raises(RuntimeError) as e:
        await creds.get_frozen_credentials()
    assert error_message in str(e) 


@pytest.mark.moto
@pytest.mark.asyncio
async def test_partial_creds_is_an_error():
    # If the user provides an access key, they must also
    # provide a secret key.  Not doing so will generate an
    # error.
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        # Missing the AWS_SECRET_ACCESS_KEY
    }
    provider = credentials.EnvProvider(environ)
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_access_key_id_raises_error():
    expiry_time = datetime.now(tzlocal()) - timedelta(hours=1)
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()

    del environ['AWS_ACCESS_KEY_ID']

    # Since the credentials are expired, we'll trigger a refresh
    # whenever we try to access them. At that refresh time, the relevant
    # environment variables are incomplete, so an error will be raised.
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await creds.get_frozen_credentials()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_refresh():
    # First initialize the credentials with an expired credential set.
    expiry_time = datetime.now(tzlocal()) - timedelta(hours=1)
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()
    assert isinstance(creds, credentials.RefreshableCredentials) is True

    # Since the credentials are expired, we'll trigger a refresh whenever
    # we try to access them. But at this point the environment hasn't been
    # updated, so when it refreshes it will trigger an exception because
    # the new creds are still expired.
    error_message = (
        "Credentials were refreshed, but the refreshed credentials are "
        "still expired."
    )
    with pytest.raises(RuntimeError) as e:
        await creds.get_frozen_credentials()

    assert error_message in str(e)

    # Now we update the environment with non-expired credentials,
    # so when we access the creds it will refresh and grab the new ones.
    expiry_time = datetime.now(tzlocal()) + timedelta(hours=1)
    environ.update({
        'AWS_ACCESS_KEY_ID': 'bin',
        'AWS_SECRET_ACCESS_KEY': 'bam',
        'AWS_SESSION_TOKEN': 'biz',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    })

    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'bin'
    assert frozen.secret_key == 'bam'
    assert frozen.token == 'biz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_only_refresh_when_needed():
    expiry_time = datetime.now(tzlocal()) + timedelta(hours=2)
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    }
    provider = credentials.EnvProvider(environ)

    # Perform the initial credential load
    creds = await provider.load()

    # Now that the initial load has been performed, we go ahead and
    # change the environment. If the credentials were expired,
    # they would immediately refresh upon access and we'd get the new
    # ones. Since they've got plenty of time, they shouldn't refresh.
    expiry_time = datetime.now(tzlocal()) + timedelta(hours=3)
    environ.update({
        'AWS_ACCESS_KEY_ID': 'bin',
        'AWS_SECRET_ACCESS_KEY': 'bam',
        'AWS_SESSION_TOKEN': 'biz',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    })

    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'foo'
    assert frozen.secret_key == 'bar'
    assert frozen.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_not_refreshable_if_no_expiry_present():
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()
    assert isinstance(creds, credentials.RefreshableCredentials) is False
    assert isinstance(creds, credentials.Credentials) is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_do_not_become_refreshable():
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_SESSION_TOKEN': 'baz',
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()
    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'foo'
    assert frozen.secret_key == 'bar'
    assert frozen.token == 'baz'

    expiry_time = datetime.now(tzlocal()) - timedelta(hours=1)
    environ.update({
        'AWS_ACCESS_KEY_ID': 'bin',
        'AWS_SECRET_ACCESS_KEY': 'bam',
        'AWS_SESSION_TOKEN': 'biz',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    })

    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'foo'
    assert frozen.secret_key == 'bar'
    assert frozen.token == 'baz'
    assert isinstance(creds, credentials.RefreshableCredentials) is False


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_throw_error_if_expiry_goes_away():
    expiry_time = datetime.now(tzlocal()) - timedelta(hours=1)
    environ = {
        'AWS_ACCESS_KEY_ID': 'foo',
        'AWS_SECRET_ACCESS_KEY': 'bar',
        'AWS_CREDENTIAL_EXPIRATION': expiry_time.isoformat(),
    }
    provider = credentials.EnvProvider(environ)
    creds = await provider.load()

    del environ['AWS_CREDENTIAL_EXPIRATION']

    with pytest.raises(credentials.PartialCredentialsError):
        await creds.get_frozen_credentials()

#######################################
# class TestSharedCredentialsProvider #
#######################################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_credential_file_exists_default_profile():
    ini_parser = mock.Mock(return_value={
        'default': {
            'aws_access_key_id': 'foo',
            'aws_secret_access_key': 'bar',
        }
    })
    provider = credentials.SharedCredentialProvider(
        creds_filename='~/.aws/creds', profile_name='default',
        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token is None
    assert creds.method == 'shared-credentials-file'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_partial_creds_raise_error():
    ini_parser = mock.Mock(return_value={
        'default': {
            'aws_access_key_id': 'foo',
            # Missing 'aws_secret_access_key'.
        }
    })
    provider = credentials.SharedCredentialProvider(
        creds_filename='~/.aws/creds', profile_name='default',
        ini_parser=ini_parser)
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_file_exists_with_session_token():
    ini_parser = mock.Mock(return_value={
        'default': {
            'aws_access_key_id': 'foo',
            'aws_secret_access_key': 'bar',
            'aws_session_token': 'baz',
        }
    })
    provider = credentials.SharedCredentialProvider(
        creds_filename='~/.aws/creds', profile_name='default',
        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    assert creds.method == 'shared-credentials-file'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_file_with_multiple_profiles():
    ini_parser = mock.Mock(return_value={
        # Here the user has a 'default' and a 'dev' profile.
        'default': {
            'aws_access_key_id': 'a',
            'aws_secret_access_key': 'b',
            'aws_session_token': 'c',
        },
        'dev': {
            'aws_access_key_id': 'd',
            'aws_secret_access_key': 'e',
            'aws_session_token': 'f',
        },
    })
    # And we specify a profile_name of 'dev'.
    provider = credentials.SharedCredentialProvider(
        creds_filename='~/.aws/creds', profile_name='dev',
        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'd'
    assert creds.secret_key == 'e'
    assert creds.token == 'f'
    assert creds.method == 'shared-credentials-file'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credentials_file_does_not_exist_returns_none():
    # It's ok if the credentials file does not exist, we should
    # just catch the appropriate errors and return None.
    ini_parser = mock.Mock(side_effect=botocore.exceptions.ConfigNotFound(
        path='foo'))
    provider = credentials.SharedCredentialProvider(
        creds_filename='~/.aws/creds', profile_name='dev',
        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is None

################################
# class TestConfigFileProvider #
################################
@pytest.fixture
def config_file_parser():
    profile_config = {
        'aws_access_key_id': 'a',
        'aws_secret_access_key': 'b',
        'aws_session_token': 'c',
        # Non creds related configs can be in a session's # config.
        'region': 'us-west-2',
        'output': 'json',
    }
    parsed = {'profiles': {'default': profile_config}}
    parser = mock.Mock()
    parser.return_value = parsed
    return parser


@pytest.mark.moto
@pytest.mark.asyncio
async def test_config_file_exists(config_file_parser):
    provider = credentials.ConfigProvider('cli.cfg', 'default',
                                          config_file_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'
    assert creds.method == 'config-file'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_config_file_missing_profile_config(config_file_parser):
    # Referring to a profile that's not in the config file
    # will result in session.config returning an empty dict.
    profile_name = 'NOT-default'
    provider = credentials.ConfigProvider('cli.cfg', profile_name,
                                          config_file_parser)
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_config_file_errors_ignored(config_file_parser):
    # We should move on to the next provider if the config file
    # can't be found.
    config_file_parser.side_effect = botocore.exceptions.ConfigNotFound(
        path='cli.cfg')
    provider = credentials.ConfigProvider('cli.cfg', 'default',
                                          config_file_parser)
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_partial_creds_is_error():
    profile_config = {
        'aws_access_key_id': 'a',
        # Missing aws_secret_access_key
    }
    parsed = {'profiles': {'default': profile_config}}
    parser = mock.Mock()
    parser.return_value = parsed
    provider = credentials.ConfigProvider('cli.cfg', 'default', parser)
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


##########################
# class TestBotoProvider #
##########################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_boto_config_file_exists_in_home_dir():
    environ = {}
    ini_parser = mock.Mock(return_value={
        'Credentials': {
            # boto's config file does not support a session token
            # so we only test for access_key/secret_key.
            'aws_access_key_id': 'a',
            'aws_secret_access_key': 'b',
        }
    })
    provider = credentials.BotoProvider(environ=environ,
                                        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token is None
    assert creds.method == 'boto-config'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_env_var_set_for_boto_location():
    environ = {
        'BOTO_CONFIG': 'alternate-config.cfg'
    }
    ini_parser = mock.Mock(return_value={
        'Credentials': {
            # boto's config file does not support a session token
            # so we only test for access_key/secret_key.
            'aws_access_key_id': 'a',
            'aws_secret_access_key': 'b',
        }
    })
    provider = credentials.BotoProvider(environ=environ,
                                        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token is None
    assert creds.method == 'boto-config'

    # Assert that the parser was called with the filename specified
    # in the env var.
    ini_parser.assert_called_with('alternate-config.cfg')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_no_boto_config_file_exists():
    ini_parser = mock.Mock(side_effect=botocore.exceptions.ConfigNotFound(
        path='foo'))
    provider = credentials.BotoProvider(environ={},
                                        ini_parser=ini_parser)
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_partial_creds_is_error():
    ini_parser = mock.Mock()
    ini_parser.return_value = {
        'Credentials': {
            'aws_access_key_id': 'a',
            # Missing aws_secret_access_key.
        }
    }
    provider = credentials.BotoProvider(environ={},
                                        ini_parser=ini_parser)
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


#################################
# class TestOriginalEC2Provider #
#################################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_ec2_credentials_file_not_exist():
    provider = credentials.OriginalEC2Provider(environ={})
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_ec2_credentials_file_exists():
    environ = {
        'AWS_CREDENTIAL_FILE': 'foo.cfg',
    }
    parser = mock.Mock()
    parser.return_value = {
        'AWSAccessKeyId': 'a',
        'AWSSecretKey': 'b',
    }
    provider = credentials.OriginalEC2Provider(environ=environ,
                                               parser=parser)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token is None
    assert creds.method == 'ec2-credentials-file'



######################################
# class TestInstanceMetadataProvider #
######################################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_from_instance_metadata():
    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()
    fetcher = mock.Mock()
    fetcher.retrieve_iam_role_credentials = asynctest.CoroutineMock(return_value={
        'access_key': 'a',
        'secret_key': 'b',
        'token': 'c',
        'expiry_time': timestamp,
        'role_name': 'myrole',
    })
    provider = credentials.InstanceMetadataProvider(
        iam_role_fetcher=fetcher)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'
    assert creds.method == 'iam-role'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_no_role_creds_exist():
    fetcher = mock.Mock()
    fetcher.retrieve_iam_role_credentials = asynctest.CoroutineMock(return_value={})
    provider = credentials.InstanceMetadataProvider(
        iam_role_fetcher=fetcher)
    creds = await provider.load()
    assert creds is None
    fetcher.retrieve_iam_role_credentials.assert_called_with()


################################
# class CredentialResolverTest #
################################
@pytest.fixture
def fake_creds():
    return credentials.Credentials('a', 'b', 'c')


@pytest.fixture
def provider1():
    provider1 = mock.Mock()
    provider1.METHOD = 'provider1'
    provider1.CANONICAL_NAME = 'CustomProvider1'
    return provider1


@pytest.fixture
def provider2():
    provider2 = mock.Mock()
    provider2.METHOD = 'provider2'
    provider2.CANONICAL_NAME = 'CustomProvider2'
    return provider2


@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_credentials_single_provider(fake_creds, provider1):
    provider1.load = asynctest.CoroutineMock(return_value=fake_creds)
    resolver = credentials.CredentialResolver(providers=[provider1])
    creds = await resolver.load_credentials()
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'


@pytest.mark.moto
def test_get_provider_by_name(provider1):
    resolver = credentials.CredentialResolver(providers=[provider1])
    result = resolver.get_provider('provider1')
    assert result is provider1


@pytest.mark.moto
def test_get_unknown_provider_raises_error(provider1):
    resolver = credentials.CredentialResolver(providers=[provider1])
    with pytest.raises(botocore.exceptions.UnknownCredentialError):
        resolver.get_provider('unknown-foo')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_first_credential_non_none_wins(provider1, provider2, fake_creds):
    provider1.load = asynctest.CoroutineMock(return_value=None)
    provider2.load = asynctest.CoroutineMock(return_value=fake_creds)
    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    creds = await resolver.load_credentials()
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token ==  'c'
    provider1.load.assert_called_with()
    provider2.load.assert_called_with()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_no_creds_loaded(provider1, provider2):
    provider1.load = asynctest.CoroutineMock(return_value=None)
    provider2.load = asynctest.CoroutineMock(return_value=None)
    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    creds = await resolver.load_credentials()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_inject_additional_providers_after_existing(provider1, provider2, fake_creds):
    provider1.load = asynctest.CoroutineMock(return_value=None)
    provider2.load = asynctest.CoroutineMock(return_value=fake_creds)
    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    # Now, if we were to call resolver.load() now, provider2 would
    # win because it's returning a non None response.
    # However we can inject a new provider before provider2 to
    # override this process.
    # Providers can be added by the METHOD name of each provider.
    new_provider = mock.Mock()
    new_provider.METHOD = 'new_provider'

    new_provider.load =asynctest.CoroutineMock(return_value=credentials.Credentials('d', 'e', 'f'))

    resolver.insert_after('provider1', new_provider)

    creds = await resolver.load_credentials()
    assert creds is not None

    assert creds.access_key == 'd'
    assert creds.secret_key == 'e'
    assert creds.token == 'f'
    # Provider 1 should have been called, but provider2 should
    # *not* have been called because new_provider already returned
    # a non-None response.
    provider1.load.assert_called_with()
    assert provider2.called is False


@pytest.mark.moto
@pytest.mark.asyncio
async def test_inject_provider_before_existing(provider1, provider2):
    new_provider = mock.Mock()
    new_provider.METHOD = 'override'

    new_provider.load = asynctest.CoroutineMock(return_value=credentials.Credentials('x', 'y', 'z'))

    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    resolver.insert_before(provider1.METHOD, new_provider)
    creds = await resolver.load_credentials()
    assert creds.access_key == 'x'
    assert creds.secret_key == 'y'
    assert creds.token == 'z'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_remove_providers(provider1, provider2):
    provider1.load = asynctest.CoroutineMock(return_value=credentials.Credentials(
        'a', 'b', 'c'))
    provider2.load= asynctest.CoroutineMock(return_value=credentials.Credentials(
        'd', 'e', 'f'))
    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    resolver.remove('provider1')
    creds = await resolver.load_credentials()
    assert creds is not None
    assert creds.access_key == 'd'
    assert creds.secret_key == 'e'
    assert creds.token == 'f'
    assert provider1.load.called is False
    provider2.load.assert_called_with()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_provider_unknown(provider1, provider2):
    resolver = credentials.CredentialResolver(providers=[provider1, provider2])
    # No error is raised if you try to remove an unknown provider.
    resolver.remove('providerFOO')
    # But an error IS raised if you try to insert after an unknown
    # provider.
    with pytest.raises(botocore.exceptions.UnknownCredentialError):
        resolver.insert_after('providerFoo', None)


######################################
# class TestCreateCredentialResolver #
######################################
@pytest.fixture
def session_instance_vars():
    return {
            'credentials_file': 'a',
            'legacy_config_file': 'b',
            'config_file': 'c',
            'metadata_service_timeout': 'd',
            'metadata_service_num_attempts': 'e',
        }


@pytest.fixture
def fake_env_vars():
    return {}


@pytest.fixture
def session(session_instance_vars, fake_env_vars):
    def fake_get_config_variable(name, methods=None):
        if methods == ('instance',):
            return session_instance_vars.get(name)
        elif methods is not None and 'env' in methods:
            return fake_env_vars.get(name)
    session = mock.Mock()
    session.get_config_variable = fake_get_config_variable
    return session


@pytest.mark.moto
@pytest.mark.asyncio
async def test_create_credential_resolver(session):
    resolver = credentials.create_credential_resolver(session)
    assert isinstance(resolver, credentials.CredentialResolver) is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_explicit_profile_ignores_env_provider(session_instance_vars, session):
    session_instance_vars['profile'] = 'dev'
    resolver = credentials.create_credential_resolver(session)

    assert all(not isinstance(p, EnvProvider) for p in resolver.providers) is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_no_profile_checks_env_provider(session_instance_vars, session):
    # If no profile is provided,
    session_instance_vars.pop('profile', None)
    resolver = credentials.create_credential_resolver(session)
    # Then an EnvProvider should be part of our credential lookup chain.
    assert any(isinstance(p, EnvProvider) for p in resolver.providers) is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_env_provider_added_if_profile_from_env_set(session, fake_env_vars):
    fake_env_vars['profile'] = 'profile-from-env'
    resolver = credentials.create_credential_resolver(session, fake_env_vars)
    assert any(isinstance(p, EnvProvider) for p in resolver.providers) is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_default_cache(session):
    resolver = credentials.create_credential_resolver(session)
    cache = resolver.get_provider('assume-role').cache
    assert isinstance(cache, dict) is True
    assert cache == {}


@pytest.mark.moto
@pytest.mark.asyncio
async def test_custom_cache(session):
    custom_cache = credentials.JSONFileCache()
    resolver = credentials.create_credential_resolver(
        session, custom_cache
    )
    cache = resolver.get_provider('assume-role').cache
    assert cache is custom_cache



#########################################
# class TestCanonicalNameSourceProvider #
#########################################
@pytest.fixture
def custom_provider1():
    provider1 = mock.Mock(spec=CredentialProvider)
    provider1.METHOD = 'provider1'
    provider1.CANONICAL_NAME = 'CustomProvider1'
    return provider1


@pytest.fixture
def custom_provider2():
    provider2 = mock.Mock(spec=CredentialProvider)
    provider2.METHOD = 'provider2'
    provider2.CANONICAL_NAME = 'CustomProvider2'
    return provider2


@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_source_credentials(custom_provider1, custom_provider2, fake_creds):
    provider = credentials.CanonicalNameCredentialSourcer(providers=[
        custom_provider1, custom_provider2
    ])
    custom_provider1.load = asynctest.CoroutineMock(return_value=fake_creds)
    result = await provider.source_credentials('CustomProvider1')
    assert result is fake_creds


@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_source_credentials_case_insensitive(custom_provider1, custom_provider2, fake_creds):
    provider = credentials.CanonicalNameCredentialSourcer(providers=[
        custom_provider1, custom_provider2
    ])
    custom_provider1.load = asynctest.CoroutineMock(return_value=fake_creds)
    result = await provider.source_credentials('cUsToMpRoViDeR1')
    assert result is fake_creds


@pytest.mark.moto
@pytest.mark.asyncio
async def test_load_unknown_canonical_name_raises_error(custom_provider1):
    provider = credentials.CanonicalNameCredentialSourcer(providers=[
        custom_provider1])
    with pytest.raises(botocore.exceptions.UnknownCredentialError):
        await provider.source_credentials('CustomUnknown')


async def _assert_assume_role_creds_returned_with_shared_file(provider, fake_creds):
    assume_role_provider = mock.Mock(spec=AssumeRoleProvider)
    assume_role_provider.METHOD = 'assume-role'
    assume_role_provider.CANONICAL_NAME = None

    source = credentials.CanonicalNameCredentialSourcer(providers=[
        assume_role_provider, provider
    ])

    # If the assume role provider returns credentials, those should be
    # what is returned.
    assume_role_provider.load = asynctest.CoroutineMock(return_value=fake_creds)
    provider.load = asynctest.CoroutineMock(return_value=credentials.Credentials(
        'd', 'e', 'f'
    ))

    creds = await source.source_credentials(provider.CANONICAL_NAME)
    assert creds is not None
    assert creds.access_key, 'a'
    assert creds.secret_key, 'b'
    assert creds.token, 'c'
    assert provider.load.called is False


async def _assert_returns_creds_if_assume_role_not_used(provider):
    assume_role_provider = mock.Mock(spec=AssumeRoleProvider)
    assume_role_provider.METHOD = 'assume-role'
    assume_role_provider.CANONICAL_NAME = None

    source = credentials.CanonicalNameCredentialSourcer(providers=[
        assume_role_provider, provider
    ])

    # If the assume role provider returns nothing, then whatever is in
    # the config provider should be returned.
    assume_role_provider.load = asynctest.CoroutineMock(return_value=None)
    provider.load = asynctest.CoroutineMock(return_value=credentials.Credentials(
        'd', 'e', 'f'
    ))

    creds = await source.source_credentials(provider.CANONICAL_NAME)
    assert creds is not None
    assert creds.access_key == 'd'
    assert creds.secret_key == 'e'
    assert creds.token == 'f'
    assert assume_role_provider.load.called is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_creds_returned_with_config_file(fake_creds):
    provider = mock.Mock(spec=ConfigProvider)
    provider.METHOD = 'config-file'
    provider.CANONICAL_NAME = 'SharedConfig'
    await _assert_assume_role_creds_returned_with_shared_file(provider, fake_creds)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_config_file_returns_creds_if_assume_role_not_used():
    provider = mock.Mock(spec=ConfigProvider)
    provider.METHOD = 'config-file'
    provider.CANONICAL_NAME = 'SharedConfig'
    await _assert_returns_creds_if_assume_role_not_used(provider)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_creds_returned_with_cred_file(fake_creds):
    provider = mock.Mock(spec=SharedCredentialProvider)
    provider.METHOD = 'credentials-file'
    provider.CANONICAL_NAME = 'SharedCredentials'
    await _assert_assume_role_creds_returned_with_shared_file(provider, fake_creds)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_creds_file_returns_creds_if_assume_role_not_used():
    provider = mock.Mock(spec=SharedCredentialProvider)
    provider.METHOD = 'credentials-file'
    provider.CANONICAL_NAME = 'SharedCredentials'
    await _assert_returns_creds_if_assume_role_not_used(provider)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_get_canonical_assume_role_without_shared_files(fake_creds):
    assume_role_provider = mock.Mock(spec=AssumeRoleProvider)
    assume_role_provider.METHOD = 'assume-role'
    assume_role_provider.CANONICAL_NAME = None
    assume_role_provider.load = asynctest.CoroutineMock(return_value=fake_creds)

    provider = credentials.CanonicalNameCredentialSourcer(providers=[
        assume_role_provider
    ])

    creds = await provider.source_credentials('SharedConfig')
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'

    creds = await provider.source_credentials('SharedCredentials')
    assert creds is not None
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_get_canonical_shared_files_without_assume_role(custom_provider1):
    provider = credentials.CanonicalNameCredentialSourcer(
        providers=[custom_provider1])
    with pytest.raises(botocore.exceptions.UnknownCredentialError):
        await provider.source_credentials('SharedConfig')
    with pytest.raises(botocore.exceptions.UnknownCredentialError):
        await provider.source_credentials('SharedCredentials')



##########################################
# class TestAssumeRoleCredentialProvider #
##########################################
@pytest.fixture
def fake_config():
    return {
        'profiles': {
            'development': {
                'role_arn': 'myrole',
                'source_profile': 'longterm',
            },
            'longterm': {
                'aws_access_key_id': 'akid',
                'aws_secret_access_key': 'skid',
            },
            'non-static': {
                'role_arn': 'myrole',
                'credential_source': 'Environment'
            },
            'chained': {
                'role_arn': 'chained-role',
                'source_profile': 'development'
            }
        }
    }


def create_config_loader(fake_config, with_config=None):
    if with_config is None:
        with_config = fake_config
    load_config = mock.Mock()
    load_config.return_value = with_config
    return load_config


def create_client_creator(with_response):
    # Create a mock sts client that returns a specific response
    # for assume_role.
    client = mock.Mock()
    if isinstance(with_response, list):
        client.assume_role = asynctest.CoroutineMock(side_effect=with_response)
    else:
        client.assume_role = asynctest.CoroutineMock(return_value=with_response)
    return mock.Mock(return_value=client)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_with_no_cache(fake_config):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache={}, profile_name='development')

    creds = await provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_with_datetime(fake_config):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # Note the lack of isoformat(), we're using
            # a datetime.datetime type.  This will ensure
            # we test both parsing as well as serializing
            # from a given datetime because the credentials
            # are immediately expired.
            'Expiration': datetime.now(tzlocal()) + timedelta(hours=20)
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache={}, profile_name='development')

    creds = await provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_refresher_serializes_datetime(fake_config):
    client = mock.Mock()
    time_zone = tzutc()
    expiration = datetime(
        year=2016, month=11, day=6, hour=1, minute=30, tzinfo=time_zone)
    client.assume_role = asynctest.CoroutineMock(return_value={
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': expiration,
        }
    })
    refresh = create_assume_role_refresher(client, {})
    expiry_time = (await refresh())['expiry_time']
    assert expiry_time == '2016-11-06T01:30:00UTC'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_retrieves_from_cache(fake_config):
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'
    fake_config['profiles']['development']['role_arn'] = 'myrole'

    cache_key = (
        '793d6e2f27667ab2da104824407e486bfec24a47'
    )
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            }
        }
    }
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), mock.Mock(),
        cache=cache, profile_name='development')

    creds = await provider.load()

    assert creds.access_key == 'foo-cached'
    assert creds.secret_key == 'bar-cached'
    assert creds.token == 'baz-cached'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_chain_prefers_cache(fake_config):
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'

    # The profile we will be using has a cache entry, but the profile it
    # is sourcing from does not. This should result in the cached
    # credentials being used, and the source profile not being called.
    cache_key = (
        '3d440bf424caf7a5ee664fbf89139a84409f95c2'
    )
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            }
        }
    }
    expiration_in_future = datetime.utcnow() + timedelta(seconds=3000)
    expiration = expiration_in_future.isoformat() + 'Z'
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': expiration,
        }
    }
    client_creator = create_client_creator(with_response=response)

    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), client_creator,
        cache=cache, profile_name='chained')

    creds = await provider.load()

    assert creds.access_key == 'foo-cached'
    assert creds.secret_key == 'bar-cached'
    assert creds.token == 'baz-cached'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_cache_key_is_windows_safe(fake_config):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    cache = {}
    fake_config['profiles']['development']['role_arn'] = (
        'arn:aws:iam::foo-role')

    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache=cache, profile_name='development')

    await (await provider.load()).get_frozen_credentials()
    # On windows, you cannot use a a ':' in the filename, so
    # we need to make sure it doesn't come up in the cache key.
    cache_key = (
        '3f8e35c8dca6211d496e830a2de723b2387921e3'
    )
    assert cache_key in cache
    assert cache[cache_key] == response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_cache_key_with_role_session_name(fake_config):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    cache = {}
    fake_config['profiles']['development']['role_arn'] = (
        'arn:aws:iam::foo-role')
    fake_config['profiles']['development']['role_session_name'] = (
        'foo_role_session_name')

    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache=cache, profile_name='development')

    # The credentials won't actually be assumed until they're requested.
    await (await provider.load()).get_frozen_credentials()

    cache_key = (
        '5e75ce21b6a64ab183b29c4a159b6f0248121d51'
    )
    assert cache_key in cache
    assert cache[cache_key] == response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_in_cache_but_expired(fake_config):
    expired_creds = datetime.now(tzlocal())
    valid_creds = expired_creds + timedelta(hours=1)
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': valid_creds,
        },
    }
    client_creator = create_client_creator(with_response=response)
    cache = {
        'development--myrole': {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': expired_creds,
            }
        }
    }
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), client_creator,
        cache=cache, profile_name='development')

    creds = await provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_role_session_name_provided(fake_config):
    dev_profile = fake_config['profiles']['development']
    dev_profile['role_session_name'] = 'myname'
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache={}, profile_name='development')

    # The credentials won't actually be assumed until they're requested.
    await (await provider.load()).get_frozen_credentials()

    client = client_creator.return_value
    client.assume_role.assert_called_with(
        RoleArn='myrole', RoleSessionName='myname')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_external_id_provided(fake_config):
    fake_config['profiles']['development']['external_id'] = 'myid'
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        client_creator, cache={}, profile_name='development')

    # The credentials won't actually be assumed until they're requested.
    await (await provider.load()).get_frozen_credentials()

    client = client_creator.return_value
    client.assume_role.assert_called_with(
        RoleArn='myrole', ExternalId='myid', RoleSessionName=mock.ANY)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_with_mfa(fake_config):
    fake_config['profiles']['development']['mfa_serial'] = 'mfa'
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    prompter = mock.Mock(return_value='token-code')
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), client_creator,
        cache={}, profile_name='development', prompter=prompter)

    # The credentials won't actually be assumed until they're requested.
    await (await provider.load()).get_frozen_credentials()

    client = client_creator.return_value
    # In addition to the normal assume role args, we should also
    # inject the serial number from the config as well as the
    # token code that comes from prompting the user (the prompter
    # object).
    client.assume_role.assert_called_with(
        RoleArn='myrole', RoleSessionName=mock.ANY, SerialNumber='mfa',
        TokenCode='token-code')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_populates_session_name_on_refresh(fake_config):
    expiration_time = some_future_time()
    next_expiration_time = expiration_time + timedelta(hours=4)
    responses = [{
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # We're creating an expiry time in the past so as
            # soon as we try to access the credentials, the
            # refresh behavior will be triggered.
            'Expiration': expiration_time.isoformat(),
        },
    }, {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': next_expiration_time.isoformat(),
        }
    }]
    client_creator = create_client_creator(with_response=responses)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), client_creator,
        cache={}, profile_name='development',
        prompter=mock.Mock(return_value='token-code'))

    local_now = mock.Mock(return_value=datetime.now(tzlocal()))
    with asynctest.mock.patch('aiobotocore.credentials._local_now', local_now):
        # This will trigger the first assume_role() call.  It returns
        # credentials that are expired and will trigger a refresh.
        creds = await provider.load()
        await creds.get_frozen_credentials()

        # This will trigger the second assume_role() call because
        # a refresh is needed.
        local_now.return_value = expiration_time
        await creds.get_frozen_credentials()

    client = client_creator.return_value
    assume_role_calls = client.assume_role.call_args_list
    assert len(assume_role_calls) == 2
    # The args should be identical.  That is, the second
    # assume_role call should have the exact same args as the
    # initial assume_role call.
    assert assume_role_calls[0] == assume_role_calls[1]


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_mfa_cannot_refresh_credentials(fake_config):
    # Note: we should look into supporting optional behavior
    # in the future that allows for reprompting for credentials.
    # But for now, if we get temp creds with MFA then when those
    # creds expire, we can't refresh the credentials.
    fake_config['profiles']['development']['mfa_serial'] = 'mfa'
    expiration_time = some_future_time()
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            # We're creating an expiry time in the past so as
            # soon as we try to access the credentials, the
            # refresh behavior will be triggered.
            'Expiration': expiration_time.isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config), client_creator,
        cache={}, profile_name='development',
        prompter=mock.Mock(return_value='token-code'))

    local_now = mock.Mock(return_value=datetime.now(tzlocal()))
    with mock.patch('aiobotocore.credentials._local_now', local_now):
        # Loads the credentials, resulting in the first assume role call.
        creds = await provider.load()
        await creds.get_frozen_credentials()

        local_now.return_value = expiration_time
        with pytest.raises(credentials.RefreshWithMFAUnsupportedError):
            await creds._refresh()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_no_config_is_noop(fake_config):
    fake_config['profiles']['development'] = {
        'aws_access_key_id': 'foo',
        'aws_secret_access_key': 'bar',
    }
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='development')

    # Because a role_arn was not specified, the AssumeRoleProvider
    # is a noop and will not return credentials (which means we
    # move on to the next provider).
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_source_profile_not_provided(fake_config):
    del fake_config['profiles']['development']['source_profile']
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='development')

    # source_profile is required, we shoudl get an error.
    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_source_profile_does_not_exist(fake_config):
    dev_profile = fake_config['profiles']['development']
    dev_profile['source_profile'] = 'does-not-exist'
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='development')

    # source_profile is required, we shoudl get an error.
    with pytest.raises(botocore.exceptions.InvalidConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_incomplete_source_credentials_raises_error(fake_config):
    del fake_config['profiles']['longterm']['aws_access_key_id']
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='development')

    with pytest.raises(botocore.exceptions.PartialCredentialsError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_source_profile_and_credential_source_provided(fake_config):
    profile = fake_config['profiles']['development']
    profile['credential_source'] = 'SomeCredentialProvider'
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='development')

    with pytest.raises(botocore.exceptions.InvalidConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credential_source_with_no_resolver_configured(fake_config):
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='non-static')

    with pytest.raises(botocore.exceptions.InvalidConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credential_source_with_no_providers_configured(fake_config):
    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='non-static',
        credential_sourcer=credentials.CanonicalNameCredentialSourcer([])
    )

    with pytest.raises(botocore.exceptions.InvalidConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credential_source_not_among_providers(fake_config):
    fake_provider = mock.Mock()
    fake_provider.CANONICAL_NAME = 'CustomFakeProvider'

    provider = credentials.AssumeRoleProvider(
        create_config_loader(fake_config),
        mock.Mock(), cache={}, profile_name='non-static',
        credential_sourcer=credentials.CanonicalNameCredentialSourcer(
            [fake_provider])
    )

    # We configured the assume role provider with a single fake source
    # provider, CustomFakeProvider. The profile we are attempting to use
    # calls for the Environment credential provider as the credentials
    # source. Since that isn't one of the configured source providers,
    # an error is thrown.
    with pytest.raises(botocore.exceptions.InvalidConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_assume_role_with_credential_source(fake_config):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    client_creator = create_client_creator(with_response=response)

    config = {
        'profiles': {
            'sourced': {
                'role_arn': 'myrole',
                'credential_source': 'CustomMockProvider'
            }
        }
    }
    config_loader = create_config_loader(fake_config, with_config=config)

    fake_provider = mock.Mock()
    fake_provider.CANONICAL_NAME = 'CustomMockProvider'
    fake_creds = credentials.Credentials(
        'akid', 'skid', 'token'
    )
    fake_provider.load = asynctest.CoroutineMock(return_value=fake_creds)

    provider = credentials.AssumeRoleProvider(
        config_loader, client_creator, cache={}, profile_name='sourced',
        credential_sourcer=credentials.CanonicalNameCredentialSourcer(
            [fake_provider])
    )

    creds = await provider.load()
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    client_creator.assert_called_with(
        'sts', aws_access_key_id=fake_creds.access_key,
        aws_secret_access_key=fake_creds.secret_key,
        aws_session_token=fake_creds.token
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_credential_source_returns_none(fake_config):
    config = {
        'profiles': {
            'sourced': {
                'role_arn': 'myrole',
                'credential_source': 'CustomMockProvider'
            }
        }
    }
    config_loader = create_config_loader(fake_config, with_config=config)

    fake_provider = mock.Mock()
    fake_provider.CANONICAL_NAME = 'CustomMockProvider'
    fake_provider.load = asynctest.CoroutineMock(return_value=None)

    provider = credentials.AssumeRoleProvider(
        config_loader, mock.Mock(), cache={}, profile_name='sourced',
        credential_sourcer=credentials.CanonicalNameCredentialSourcer(
            [fake_provider])
    )

    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_source_profile_can_reference_self():
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': some_future_time().isoformat()
        },
    }
    client_creator = create_client_creator(with_response=response)

    config = {
        'profiles': {
            'self-referencial': {
                'aws_access_key_id': 'akid',
                'aws_secret_access_key': 'skid',
                'role_arn': 'myrole',
                'source_profile': 'self-referencial'
            }
        }
    }

    provider = credentials.AssumeRoleProvider(
        create_config_loader(config),
        client_creator, cache={}, profile_name='self-referencial'
    )

    creds = await provider.load()
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_infinite_looping_profiles_raises_error():
    config = {
        'profiles': {
            'first': {
                'role_arn': 'first',
                'source_profile': 'second'
            },
            'second': {
                'role_arn': 'second',
                'source_profile': 'first'
            }
        }
    }

    provider = credentials.AssumeRoleProvider(
        create_config_loader(config),
        mock.Mock(), cache={}, profile_name='first'
    )

    with pytest.raises(botocore.credentials.InfiniteLoopConfigError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_recursive_assume_role():
    assume_responses = [
        Credentials('foo', 'bar', 'baz'),
        Credentials('spam', 'eggs', 'spamandegss'),
    ]
    responses = []
    for credential_set in assume_responses:
        responses.append({
            'Credentials': {
                'AccessKeyId': credential_set.access_key,
                'SecretAccessKey': credential_set.secret_key,
                'SessionToken': credential_set.token,
                'Expiration': some_future_time().isoformat()
            }
        })
    client_creator = create_client_creator(with_response=responses)

    static_credentials = Credentials('akid', 'skid')
    config = {
        'profiles': {
            'first': {
                'role_arn': 'first',
                'source_profile': 'second'
            },
            'second': {
                'role_arn': 'second',
                'source_profile': 'third'
            },
            'third': {
                'aws_access_key_id': static_credentials.access_key,
                'aws_secret_access_key': static_credentials.secret_key,
            }
        }
    }

    provider = credentials.AssumeRoleProvider(
        create_config_loader(config),
        client_creator, cache={}, profile_name='first'
    )

    creds = await provider.load()
    expected_creds = assume_responses[-1]
    assert creds.access_key == expected_creds.access_key
    assert creds.secret_key == expected_creds.secret_key
    assert creds.token == expected_creds.token

    client_creator.assert_has_calls([
        mock.call(
            'sts', aws_access_key_id=static_credentials.access_key,
            aws_secret_access_key=static_credentials.secret_key,
            aws_session_token=static_credentials.token
        ),
        mock.call(
            'sts', aws_access_key_id=assume_responses[0].access_key,
            aws_secret_access_key=assume_responses[0].secret_key,
            aws_session_token=assume_responses[0].token
        ),
    ])


#######################
# class TestJSONCache #
#######################
@pytest.fixture
def json_cache(tmpdir):
    return credentials.JSONFileCache(tmpdir)


@pytest.mark.moto
def test_supports_contains_check(json_cache):
    # By default the cache is empty because we're
    # using a new temp dir everytime.
    assert 'mykey' not in json_cache


@pytest.mark.moto
def test_add_key_and_contains_check(json_cache):
    json_cache['mykey'] = {'foo': 'bar'}
    assert 'mykey' in json_cache


@pytest.mark.moto
def test_added_key_can_be_retrieved(json_cache):
    json_cache['mykey'] = {'foo': 'bar'}
    assert json_cache['mykey'] == {'foo': 'bar'}


@pytest.mark.moto
def test_only_accepts_json_serializable_data(json_cache):
    with pytest.raises(ValueError):
        # set()'s cannot be serialized to a JSON string.
        json_cache['mykey'] = set()


@pytest.mark.moto
def test_can_override_existing_values(json_cache):
    json_cache['mykey'] = {'foo': 'bar'}
    json_cache['mykey'] = {'baz': 'newvalue'}
    assert json_cache['mykey'] == {'baz': 'newvalue'}


@pytest.mark.moto
def test_can_add_multiple_keys(json_cache):
    json_cache['mykey'] = {'foo': 'bar'}
    json_cache['mykey2'] = {'baz': 'qux'}
    assert json_cache['mykey'] == {'foo': 'bar'}
    assert json_cache['mykey2'] == {'baz': 'qux'}


@pytest.mark.moto
def test_working_dir_does_not_exist(tmpdir, json_cache):
    working_dir = os.path.join(tmpdir, 'foo')
    json_cache = credentials.JSONFileCache(working_dir)
    json_cache['foo'] = {'bar': 'baz'}
    assert json_cache['foo'] == {'bar': 'baz'}


@pytest.mark.moto
def test_key_error_raised_when_cache_key_does_not_exist(json_cache):
    with pytest.raises(KeyError):
        json_cache['foo']


@pytest.mark.moto
def t(json_cache):
    json_cache['mykey'] = {
        'really long key in the cache': 'really long value in cache'}
    # Now overwrite it with a smaller value.
    json_cache['mykey'] = {'a': 'b'}
    assert self.cache['mykey'] == {'a': 'b'}


@pytest.mark.moto
def test_permissions_for_file_restricted(tmpdir, json_cache):
    json_cache['mykey'] = {'foo': 'bar'}
    filename = os.path.join(tmpdir, 'mykey.json')
    assert os.stat(filename).st_mode & 0xFFF == 0o600


##########################
# class TestRefreshLogic #
##########################
class IntegerRefresher(credentials.RefreshableCredentials):
    """Refreshable credentials to help with testing.

    This class makes testing refreshable credentials easier.
    It has the following functionality:

        * A counter, self.refresh_counter, to indicate how many
          times refresh was called.
        * A way to specify how many seconds to make credentials
          valid.
        * Configurable advisory/mandatory refresh.
        * An easy way to check consistency.  Each time creds are
          refreshed, all the cred values are set to the next
          incrementing integer.  Frozen credentials should always
          have this value.
    """

    _advisory_refresh_timeout = 2
    _mandatory_refresh_timeout = 1
    _credentials_expire = 3

    def __init__(self, creds_last_for=_credentials_expire,
                 advisory_refresh=_advisory_refresh_timeout,
                 mandatory_refresh=_mandatory_refresh_timeout,
                 refresh_function=None):
        expires_in = (
            self._current_datetime() +
            timedelta(seconds=creds_last_for))
        if refresh_function is None:
            refresh_function = self._do_refresh
        super(IntegerRefresher, self).__init__(
            '0', '0', '0', expires_in,
            refresh_function, 'INTREFRESH')
        self.creds_last_for = creds_last_for
        self.refresh_counter = 0
        self._advisory_refresh_timeout = advisory_refresh
        self._mandatory_refresh_timeout = mandatory_refresh

    async def _do_refresh(self):
        self.refresh_counter += 1
        current = int(self._access_key)
        next_id = str(current + 1)

        return {
            'access_key': next_id,
            'secret_key': next_id,
            'token': next_id,
            'expiry_time': self._seconds_later(self.creds_last_for),
        }

    def _seconds_later(self, num_seconds):
        # We need to guarantee at *least* num_seconds.
        # Because this doesn't handle subsecond precision
        # we'll round up to the next second.
        num_seconds += 1
        t = self._current_datetime() + timedelta(seconds=num_seconds)
        return self._to_timestamp(t)

    def _to_timestamp(self, datetime_obj):
        obj = utils.parse_to_aware_datetime(datetime_obj)
        return obj.strftime('%Y-%m-%dT%H:%M:%SZ')

    def _current_timestamp(self):
        return self._to_timestamp(self._current_datetime())

    def _current_datetime(self):
        return datetime.now(tzlocal())


@pytest.mark.moto
@pytest.mark.asyncio
async def test_mandatory_refresh_needed():
    creds = IntegerRefresher(
        # These values will immediately trigger
        # a manadatory refresh.
        creds_last_for=2,
        mandatory_refresh=3,
        advisory_refresh=3)
    temp = await creds.get_frozen_credentials()
    assert temp == credentials.ReadOnlyCredentials('1', '1', '1')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_advisory_refresh_needed():
    creds = IntegerRefresher(
        # These values will immediately trigger
        # a manadatory refresh.
        creds_last_for=4,
        mandatory_refresh=2,
        advisory_refresh=5)
    temp = await creds.get_frozen_credentials()
    assert temp == credentials.ReadOnlyCredentials('1', '1', '1')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refresh_fails_is_not_an_error_during_advisory_period():
    fail_refresh = mock.Mock(side_effect=Exception("refresh failed"))
    creds = IntegerRefresher(
        creds_last_for=5,
        advisory_refresh=7,
        mandatory_refresh=3,
        refresh_function=fail_refresh
    )
    temp = await creds.get_frozen_credentials()
    # We should have called the refresh function.
    assert fail_refresh.called is True
    # The fail_refresh function will raise an exception.
    # Because we're in the advisory period we'll not propogate
    # the exception and return the current set of credentials
    # (generation '1').
    assert temp == credentials.ReadOnlyCredentials('0', '0', '0')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_exception_propogated_on_error_during_mandatory_period():
    fail_refresh = mock.Mock(side_effect=Exception("refresh failed"))
    creds = IntegerRefresher(
        creds_last_for=5,
        advisory_refresh=10,
        # Note we're in the mandatory period now (5 < 7< 10).
        mandatory_refresh=7,
        refresh_function=fail_refresh
    )
    with pytest.raises(Exception) as excinfo:
        await creds.get_frozen_credentials()
    assert "refresh failed" in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_exception_propogated_on_expired_credentials():
    fail_refresh = mock.Mock(side_effect=Exception("refresh failed"))
    creds = IntegerRefresher(
        # Setting this to 0 mean the credentials are immediately
        # expired.
        creds_last_for=0,
        advisory_refresh=10,
        mandatory_refresh=7,
        refresh_function=fail_refresh
    )
    with pytest.raises(Exception) as excinfo:
        # Because credentials are actually expired, any
        # failure to refresh should be propagated.
        await creds.get_frozen_credentials()
    assert "refresh failed" in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refresh_giving_expired_credentials_raises_exception():
    # This verifies an edge cases where refreshed credentials
    # still give expired credentials:
    # 1. We see credentials are expired.
    # 2. We try to refresh the credentials.
    # 3. The "refreshed" credentials are still expired.
    #
    # In this case, we hard fail and let the user know what
    # happened.
    creds = IntegerRefresher(
        # Negative number indicates that the credentials
        # have already been expired for 2 seconds, even
        # on refresh.
        creds_last_for=-2,
    )
    err_msg = 'refreshed credentials are still expired'
    with pytest.raises(RuntimeError) as excinfo:
        # Because credentials are actually expired, any
        # failure to refresh should be propagated.
        await creds.get_frozen_credentials()
    assert err_msg in str(excinfo.value)


###############################
# class TestContainerProvider #
###############################
@pytest.mark.moto
@pytest.mark.asyncio
async def test_noop_if_env_var_is_not_set():
    # The 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' env var
    # is not present as an env var.
    environ = {}
    provider = credentials.ContainerProvider(environ)
    creds = await provider.load()
    assert creds is None


def full_url(url):
    return 'http://%s%s' % (ContainerMetadataFetcher.IP_ADDRESS, url)


def create_fetcher():
    fetcher = mock.Mock(spec=ContainerMetadataFetcher)
    fetcher.full_url = full_url
    return fetcher


@pytest.mark.moto
@pytest.mark.asyncio
async def test_retrieve_from_provider_if_env_var_present():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': '/latest/credentials?id=foo'
    }
    fetcher = create_fetcher()
    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(return_value={
        "AccessKeyId" : "access_key",
        "SecretAccessKey" : "secret_key",
        "Token" : "token",
        "Expiration" : timestamp,
    })
    provider = credentials.ContainerProvider(environ, fetcher)
    creds = await provider.load()

    fetcher.retrieve_full_uri.assert_called_with(
        full_url('/latest/credentials?id=foo'), headers=None)
    assert creds.access_key == 'access_key'
    assert creds.secret_key == 'secret_key'
    assert creds.token == 'token'
    assert creds.method == 'container-role'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_creds_refresh_when_needed():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': '/latest/credentials?id=foo'
    }
    fetcher = mock.Mock(spec=credentials.ContainerMetadataFetcher)
    timeobj = datetime.now(tzlocal())
    expired_timestamp = (timeobj - timedelta(hours=23)).isoformat()
    future_timestamp = (timeobj + timedelta(hours=1)).isoformat()
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(side_effect=[
        {
            "AccessKeyId" : "access_key_old",
            "SecretAccessKey" : "secret_key_old",
            "Token" : "token_old",
            "Expiration" : expired_timestamp,
        },
        {
            "AccessKeyId" : "access_key_new",
            "SecretAccessKey" : "secret_key_new",
            "Token" : "token_new",
            "Expiration" : future_timestamp,
        }
    ])
    provider = credentials.ContainerProvider(environ, fetcher)
    creds = await provider.load()
    frozen_creds = await creds.get_frozen_credentials()
    assert frozen_creds.access_key == 'access_key_new'
    assert frozen_creds.secret_key == 'secret_key_new'
    assert frozen_creds.token == 'token_new'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_http_error_propagated():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': '/latest/credentials?id=foo'
    }
    fetcher = mock.Mock(spec=credentials.ContainerMetadataFetcher)
    timeobj = datetime.now(tzlocal())
    expired_timestamp = (timeobj - timedelta(hours=23)).isoformat()
    future_timestamp = (timeobj + timedelta(hours=1)).isoformat()
    exception = botocore.exceptions.CredentialRetrievalError
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(side_effect=exception(provider='ecs-role',
                                                 error_msg='fake http error'))
    with pytest.raises(exception):
        provider = credentials.ContainerProvider(environ, fetcher)
        creds = await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_http_error_propagated_on_refresh():
    # We should ensure errors are still propagated even in the
    # case of a failed refresh.
    environ = {
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': '/latest/credentials?id=foo'
    }
    fetcher = mock.Mock(spec=credentials.ContainerMetadataFetcher)
    timeobj = datetime.now(tzlocal())
    expired_timestamp = (timeobj - timedelta(hours=23)).isoformat()
    http_exception = botocore.exceptions.MetadataRetrievalError
    raised_exception = botocore.exceptions.CredentialRetrievalError
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(side_effect=[
        {
            "AccessKeyId" : "access_key_old",
            "SecretAccessKey" : "secret_key_old",
            "Token" : "token_old",
            "Expiration" : expired_timestamp,
        },
        http_exception(error_msg='HTTP connection timeout')
    ])
    provider = credentials.ContainerProvider(environ, fetcher)
    # First time works with no issues.
    creds = await provider.load()
    # Second time with a refresh should propagate an error.
    with pytest.raises(raised_exception):
        frozen_creds = await creds.get_frozen_credentials()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_use_full_url():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_FULL_URI': 'http://localhost/foo'
    }
    fetcher = create_fetcher()
    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(return_value={
        "AccessKeyId" : "access_key",
        "SecretAccessKey" : "secret_key",
        "Token" : "token",
        "Expiration" : timestamp,
    })
    provider = credentials.ContainerProvider(environ, fetcher)
    creds = await provider.load()

    fetcher.retrieve_full_uri.assert_called_with('http://localhost/foo',
                                                 headers=None)
    assert creds.access_key == 'access_key'
    assert creds.secret_key == 'secret_key'
    assert creds.token == 'token'
    assert creds.method == 'container-role'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_pass_basic_auth_token():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_FULL_URI': 'http://localhost/foo',
        'AWS_CONTAINER_AUTHORIZATION_TOKEN': 'Basic auth-token',
    }
    fetcher = create_fetcher()
    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()
    fetcher.retrieve_full_uri = asynctest.CoroutineMock(return_value={
        "AccessKeyId" : "access_key",
        "SecretAccessKey" : "secret_key",
        "Token" : "token",
        "Expiration" : timestamp,
    })
    provider = credentials.ContainerProvider(environ, fetcher)
    creds = await provider.load()

    fetcher.retrieve_full_uri.assert_called_with(
        'http://localhost/foo', headers={'Authorization': 'Basic auth-token'})
    assert creds.access_key == 'access_key'
    assert creds.secret_key == 'secret_key'
    assert creds.token == 'token'
    assert creds.method == 'container-role'


#############################
# class TestProcessProvider #
#############################
@pytest.fixture
def loaded_config():
    return {}


@pytest.fixture
def invoked_process():
    return mock.Mock()


@pytest.fixture
def popen_mock(invoked_process):
    return asynctest.CoroutineMock(return_value=invoked_process, spec=asyncio.create_subprocess_exec)


def create_process_provider(loaded_config, popen_mock, profile_name='default'):
    return credentials.ProcessProvider(
                profile_name,
                mock.Mock(return_value=loaded_config),
                popen=popen_mock)


def _get_output(stdout, stderr=''):
    return json.dumps(stdout).encode('utf-8'), stderr.encode('utf-8')


def _set_process_return_value(invoked_process, stdout, stderr='', rc=0):
    output = _get_output(stdout, stderr)
    invoked_process.communicate = asynctest.CoroutineMock(return_value=output)
    invoked_process.returncode = rc


@pytest.mark.moto
@pytest.mark.asyncio
async def test_process_not_invoked_if_profile_does_not_exist(loaded_config, popen_mock):
    # loaded_config is an empty dictionary with no profile
    # information.
    provider = create_process_provider(loaded_config, popen_mock)
    cred = await provider.load()
    assert cred is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_process_not_invoked_if_not_configured_for_empty_config(loaded_config, popen_mock):
    # No credential_process configured so we skip this provider.
    loaded_config['profiles'] = {'default': {}}
    provider = create_process_provider(loaded_config, popen_mock)
    cred = await provider.load()
    assert cred is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_retrieve_via_process(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    assert creds.method == 'custom-process'
    popen_mock.assert_called_with(
        ['my-process'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_pass_arguments_through(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {
            'credential_process': 'my-process --foo --bar "one two"'
        }
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    assert creds is not None
    popen_mock.assert_called_with(
        ['my-process', '--foo', '--bar', 'one two'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_refresh_credentials(loaded_config, popen_mock, invoked_process):
    # We given a time that's already expired so .access_key
    # will trigger the refresh worfklow.  We just need to verify
    # that the refresh function gives the same result as the
    # initial retrieval.
    expired_date = '2016-01-01T00:00:00Z'
    future_date = str(datetime.now(tzlocal()) + timedelta(hours=24))
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    old_creds = _get_output({
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': expired_date,
    })
    new_creds = _get_output({
        'Version': 1,
        'AccessKeyId': 'foo2',
        'SecretAccessKey': 'bar2',
        'SessionToken': 'baz2',
        'Expiration': future_date,
    })
    invoked_process.communicate = asynctest.CoroutineMock(side_effect=[old_creds, new_creds])
    invoked_process.returncode = 0

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    await creds.get_frozen_credentials()
    assert creds is not None
    assert creds.access_key == 'foo2'
    assert creds.secret_key == 'bar2'
    assert creds.token == 'baz2'
    assert creds.method == 'custom-process'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_non_zero_rc_raises_exception(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, '', 'Error Message', 1)

    provider = create_process_provider(loaded_config, popen_mock)
    exception = botocore.exceptions.CredentialRetrievalError
    with pytest.raises(exception) as excinfo:
        await provider.load()
    assert 'Error Message' in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_unsupported_version_raises_mismatch(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    bad_version = 100
    _set_process_return_value(invoked_process, {
        'Version': bad_version,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    exception = botocore.exceptions.CredentialRetrievalError
    with pytest.raises(exception) as excinfo:
        await provider.load()
    assert 'Unsupported version' in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_version_in_payload_returned_raises_exception(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        # Let's say they forget a 'Version' key.
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    exception = botocore.exceptions.CredentialRetrievalError
    with pytest.raises(exception) as excinfo:
        await provider.load()
    assert 'Unsupported version' in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_access_key_raises_exception(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        # Missing access key.
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    exception = botocore.exceptions.CredentialRetrievalError
    with pytest.raises(exception) as excinfo:
        await provider.load()

    assert 'Missing required key' in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_secret_key_raises_exception(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        # Missing secret key.
        'SessionToken': 'baz',
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    exception = botocore.exceptions.CredentialRetrievalError
    with pytest.raises(exception) as excinfo:
        await provider.load()
    assert 'Missing required key' in str(excinfo.value)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_session_token(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        # Missing session token.
        'Expiration': '2020-01-01T00:00:00Z',
    })

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token is None
    assert creds.method == 'custom-process'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_expiration(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'SessionToken': 'baz',
        # Missing expiration.
    })

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    assert creds.method == 'custom-process'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_missing_expiration_and_session_token(loaded_config, popen_mock, invoked_process):
    loaded_config['profiles'] = {
        'default': {'credential_process': 'my-process'}
    }
    _set_process_return_value(invoked_process, {
        'Version': 1,
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        # Missing session token and expiration
    })

    provider = create_process_provider(loaded_config, popen_mock)
    creds = await provider.load()
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token is None
    assert creds.method == 'custom-process'
