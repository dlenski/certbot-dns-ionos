"""Tests for certbot_dns_ionos.dns_ionos."""

import unittest
from uuid import uuid4
from random import randint

import mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_PREFIX = "prefix"
FAKE_SECRET = "secret"
FAKE_ENDPOINT = "mock://endpoint"

FAKE_RECORD_NAME = "foo" + str(randint(10000, 99999))
FAKE_RECORD_CONTENT = "bar" + str(randint(10000, 99999))
FAKE_RECORD_TTL = 42
FAKE_ZONE_ID = str(uuid4())
FAKE_RECORD_ID = str(uuid4())


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        from certbot_dns_ionos.dns_ionos import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "ionos_prefix": FAKE_PREFIX,
                "ionos_secret": FAKE_SECRET,
                "ionos_endpoint": FAKE_ENDPOINT,
            },
            path,
        )

        self.config = mock.MagicMock(
            ionos_credentials=path, ionos_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "ionos")

        self.mock_client = mock.MagicMock()
        # _get_ionos_client | pylint: disable=protected-access
        self.auth._get_ionos_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_matching_records(
                DOMAIN, "_acme-challenge." + DOMAIN
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)


class ionosClientTest(unittest.TestCase):
    def setUp(self):
        from certbot_dns_ionos.dns_ionos import _ionosClient
        self.client = _ionosClient(FAKE_ENDPOINT, FAKE_PREFIX, FAKE_SECRET)

    def test_add_txt_record(self):
        with requests_mock.Mocker() as m:
            mock_response = [{
                "id": FAKE_ZONE_ID,
                "name": DOMAIN,
                "type": "NATIVE"}]
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones', status_code=200, reason="OK", json=mock_response)
            mock_response = {
                "id": FAKE_ZONE_ID,
                "name": DOMAIN,
                "type": "NATIVE",
                "records": [
                    {
                    "id": FAKE_RECORD_ID,
                    "name": FAKE_RECORD_NAME,
                    "rootName": "string",
                    "type": "TXT",
                    "content": "string",
                    "changeDate": "string",
                    "ttl": 0,
                    "prio": 0,
                    "disabled": False
                    }
                ]
            }
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones/' + FAKE_ZONE_ID, status_code=200, reason="OK", json=mock_response)
            m.register_uri('PATCH', 'mock://endpoint/dns/v1/zones/' + FAKE_ZONE_ID, status_code=200, reason="OK")
            self.client.add_txt_record(
                DOMAIN, FAKE_RECORD_NAME, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL
            )

    def test_add_txt_record_fail_to_find_domain(self):
        with requests_mock.Mocker() as m:
            mock_response = [{
                "id": FAKE_ZONE_ID,
                "name": "a-different-" + DOMAIN,
                "type": "NATIVE"}]
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones', status_code=200, reason="OK", json=mock_response)
            with self.assertRaises(errors.PluginError) as context:
                self.client.add_txt_record(
                    DOMAIN, FAKE_RECORD_NAME, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL
                )

    
    def test_add_txt_record_fail_to_authenticate(self):
        with requests_mock.Mocker() as m:
            mock_response = {'message': 'Missing or invalid API key.'}
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones', status_code=401, reason="Unauthorized", json=mock_response)
            with self.assertRaises(errors.PluginError) as context:
                self.client.add_txt_record(
                    DOMAIN, FAKE_RECORD_NAME, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL
                )

    def test_del_matching_records(self):
        with requests_mock.Mocker() as m:
            mock_response = [{
                "id": FAKE_ZONE_ID,
                "name": DOMAIN,
                "type": "NATIVE"}]
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones', status_code=200, reason="OK", json=mock_response)
            mock_response = {
                "id": FAKE_ZONE_ID,
                "name": DOMAIN,
                "type": "NATIVE",
                "records": [
                    {
                    "id": FAKE_RECORD_ID,
                    "name": FAKE_RECORD_NAME,
                    "rootName": "string",
                    "type": "TXT",
                    "content": "string",
                    "changeDate": "string",
                    "ttl": 0,
                    "prio": 0,
                    "disabled": False
                    }
                ]
            }
            m.register_uri('GET', 'mock://endpoint/dns/v1/zones/' + FAKE_ZONE_ID, status_code=200, reason="OK", json=mock_response)
            m.register_uri('DELETE', 'mock://endpoint/dns/v1/zones/' + FAKE_ZONE_ID + '/records/' + FAKE_RECORD_ID, status_code=200, reason="OK")
            self.client.del_matching_records(
                DOMAIN, FAKE_RECORD_NAME
            )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
