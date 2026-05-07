"""DNS Authenticator for IONOS."""
from typing import Tuple, Any, Optional
import logging

import requests

from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for IONOS

    This Authenticator uses the IONOS Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using IONOS for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None
        self.client = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="IONOS credentials INI file.")

    def more_info(self) -> str:  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            "the IONOS Remote REST API."
        )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "IONOS credentials INI file",
            {
                "endpoint": "URL of the IONOS Remote API.",
                "prefix": "Prefix for IONOS Remote API.",
                "secret": "Secret for IONOS Remote API.",
            },
        )
        self.client = None   # recreate client after credential change

    def _perform(self, domain, validation_name, validation):
        logger.debug(f"_perform called with: domain: {domain}, validation_name: {validation_name}, validation: {validation}")
        self._get_ionos_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_ionos_client().del_matching_txt_record(
            domain, validation_name, validation
            )

    def _get_ionos_client(self) -> '_ionosClient':
        if self.client is None:
            self.client = _ionosClient(
                self.credentials.conf("endpoint"),
                self.credentials.conf("prefix"),
                self.credentials.conf("secret"),
            )
        return self.client


class _ionosClient:
    """
    Encapsulates all communication with the IONOS Remote REST API.
    """

    def __init__(self, endpoint: str, prefix: str, secret: str):
        logger.debug("creating ionosclient")
        self.endpoint = endpoint
        self.session = requests.session()
        self.session.headers['X-API-Key'] = f"{prefix}.{secret}"

    def _find_managed_zone_id(self, domain: str) -> Tuple[str, str]:
        """
        Find the Ionos DNS zone ID for a given domain. Raises a PluginError if not found.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID and name of the managed zone.
        :raises certbot.errors.PluginError: if the domain is not found.
        """
        logger.debug("get zones")
        zones = self._api_request(type='get', action="/dns/v1/zones")
        logger.debug("zones found %s", zones)
        try:
            # the domain should either be an exact match or a subdomain of
            # the zone name
            return next((zone['id'], zone['name']) for zone in zones
                        if domain == zone['name'] or domain.endswith(f".{zone['name']}"))
        except StopIteration:
            raise errors.PluginError(f"Ionos DNS account does not have a zone for {domain}")

    def _api_request(self, type: str, action: str, *args, **kwargs) -> Any:
        url = self._get_url(action)
        resp = self.session.request(type.upper(), url, *args, **kwargs)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            error_msg = resp.json()[0]['message']
            raise errors.PluginError(
                f"HTTP Error during request {resp.reason}({resp.status_code}): {error_msg}"
            ) from exc
        if type == 'get':
            try:
                return resp.json()
            except Exception as exc:
                raise errors.PluginError(
                    f"Non-JSON API response: {resp.text}"
                ) from exc

    def _get_url(self, action: str) -> str:
        return self.endpoint + action

    def add_txt_record(self, domain: str, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the IONOS API
        """
        zone_id, zone_name = self._find_managed_zone_id(domain)
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        existing_id = self.get_matching_txt_record(zone_id, record_name, record_content)
        if existing_id is not None:
            # This can only plausibly result from a previous attempt
            # at the same validation having aborted without cleanup.
            logger.warning(f"already there, id {existing_id}")
        else:
            record = [dict(content=record_content, ttl=record_ttl, name=record_name, type='TXT')]
            logger.debug("insert new txt record with data: %s", record)
            self._api_request(type='post', action=f'/dns/v1/zones/{zone_id}/records', json=record)

    def get_matching_txt_record(self, zone_id: str, record_name: str, record_content: str) -> Optional[int]:
        """
        Return the ID of an existing TXT record from the RRset for the
        given record name and content, or None if not found.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The expected validation content.
        :returns: record_id if found, otherwise None
        """
        zone_data = self._api_request(type='get', action=f'/dns/v1/zones/{zone_id}')
        for entry in zone_data['records']:
            if (
                entry["name"] == record_name
                and entry["type"] == "TXT"
            ):
                # The "content" field has an extra set of quotes glommed onto it when
                # retrieved via the API, but these are not stripped when uploaded. A
                # roundtripping bug from Ionos.
                content = entry["content"]
                if content == f'"{record_content}"':
                    return entry["id"]
                elif content == record_content:
                    logger.warning('Found matching TXT record without extra \" wrapping it. '
                                   'Ionos API may have changed.')
                    return entry["id"]

    def del_matching_txt_record(self, domain: str, record_name: str, validation: str) -> Optional[int]:
        """
        Deletes any TXT record with matching record_name and validation content,
        returning the ID of the deleted record if it was found.
        """
        zone_id, zone_name = self._find_managed_zone_id(domain)
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        primary_id = self.get_matching_txt_record(zone_id, record_name, validation)
        if primary_id is not None:
            logger.debug("delete id: %s", primary_id)
            self._api_request(type='delete', action=f'/dns/v1/zones/{zone_id}/records/{primary_id}')
            return primary_id
