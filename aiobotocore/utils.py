import os
import asyncio
import aiohttp
import logging
from botocore.exceptions import InvalidExpressionError, ConfigNotFound
from botocore.exceptions import InvalidDNSNameError, ClientError
from botocore.exceptions import MetadataRetrievalError
from botocore.compat import json, quote, zip_longest, urlsplit, urlunsplit
from botocore.compat import OrderedDict, six

from botocore.utils import (
    DEFAULT_METADATA_SERVICE_TIMEOUT, METADATA_SECURITY_CREDENTIALS_URL,
    SAFE_CHARS, LABEL_RE, S3_ACCELERATE_WHITELIST,
    _RetriesExceededError,
)


RETRYABLE_HTTP_ERRORS = [
    aiohttp.ClientConnectionError,
    aiohttp.ServerTimeoutError,
]
logger = logging.getLogger(__name__)


class PeriodicTask(object):
    def __init__(self, func, interval, loop=None):
        self.func = func
        self.interval = interval
        self._loop = loop or asyncio.get_event_loop()
        self._set()

    def _set(self):
        self._handler = self._loop.call_later(self.interval, self._run)

    def _run(self):
        try:
            self.func()
        finally:
            self._set()

    def stop(self):
        self._handler.cancel()


class ContainerMetadataFetcher(object):
    pass


class InstanceMetadataFetcher(object):
    def __init__(self, timeout=DEFAULT_METADATA_SERVICE_TIMEOUT,
                 num_attempts=1, url=METADATA_SECURITY_CREDENTIALS_URL,
                 env=None):
        self._timeout = timeout
        self._num_attempts = num_attempts
        self._url = url
        if env is None:
            env = os.environ.copy()
        self._disabled = env.get('AWS_EC2_METADATA_DISABLED', 'false').lower()
        self._disabled = self._disabled == 'true'
        self._session = aiohttp.ClientSession()

    async def _get_request(self, url, timeout, num_attempts=1):
        if self._disabled:
            logger.debug("Access to EC2 metadata has been disabled.")
            raise _RetriesExceededError()

        for i in range(num_attempts):
            try:
                response = await self._session.get(url, timeout=timeout)
            except RETRYABLE_HTTP_ERRORS as e:
                logger.debug("Caught exception while trying to retrieve "
                             "credentials: %s", e, exc_info=True)
            else:
                if response.status == 200:
                    txt = await response.text()
                    return txt, response.status
        raise _RetriesExceededError()

    async def retrieve_iam_role_credentials(self):
        data = {}
        url = self._url
        timeout = self._timeout
        num_attempts = self._num_attempts
        try:
            r, r_status_code = await self._get_request(url, timeout, num_attempts)
            if r:
                fields = r.split('\n')
                for field in fields:
                    if field.endswith('/'):
                        data[field[0:-1]] = await self.retrieve_iam_role_credentials(
                            url + field, timeout, num_attempts)
                    else:
                        val, val_status_code = await self._get_request(
                            url + field,
                            timeout=timeout,
                            num_attempts=num_attempts,
                        )
                        if val[0] == '{':
                            val = json.loads(val)
                        data[field] = val
            else:
                logger.debug("Metadata service returned non 200 status code "
                             "of %s for url: %s, content body: %s",
                             r_status_code, url, r)
        except _RetriesExceededError:
            logger.debug("Max number of attempts exceeded (%s) when "
                         "attempting to retrieve data from metadata service.",
                         num_attempts)
        # We sort for stable ordering. In practice, this should only consist
        # of one role, but may need revisiting if this expands in the future.
        final_data = {}
        for role_name in sorted(data):
            final_data = {
                'role_name': role_name,
                'access_key': data[role_name]['AccessKeyId'],
                'secret_key': data[role_name]['SecretAccessKey'],
                'token': data[role_name]['Token'],
                'expiry_time': data[role_name]['Expiration'],
            }
        return final_data
