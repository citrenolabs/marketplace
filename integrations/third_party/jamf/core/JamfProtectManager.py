from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin

import requests

from .constants import PROTECT_API_ENDPOINTS, PROTECT_PREVENT_TYPE_MAP, USER_AGENT
from .exceptions import JamfError


class JamfProtectManager:
    """
    Jamf Protect API Manager for handling authentication and GraphQL API operations
    """

    def __init__(
        self,
        api_root: str,
        client_api_id: str,
        client_api_secret: str,
        verify_ssl: bool = True,
        logger=None,
    ) -> None:
        """
        Initialize Jamf Protect Manager

        Args:
            api_root: Jamf Protect server URL (e.g., https://yourserver.jamfcloud.com)
            client_api_id: API client ID
            client_api_secret: API client secret
            verify_ssl: Whether to verify SSL certificates
            logger: Logger instance
        """
        self.api_root = (api_root or "").rstrip("/")
        self.client_api_id = client_api_id
        self.client_api_secret = client_api_secret
        self.verify_ssl = verify_ssl
        self.logger = logger

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        })

        self.access_token: Optional[str] = None
        self.token_expiration_epoch: int = 0

    def _log(self, level: str, message: str) -> None:
        if self.logger:
            getattr(self.logger, level.lower(), self.logger.info)(message)

    def _get_full_url(self, endpoint: str) -> str:
        """
        Construct full URL for API endpoint

        Args:
            endpoint: API endpoint path

        Returns:
            Full URL string
        """
        return urljoin(self.api_root, endpoint.lstrip("/"))

    def get_access_token(self) -> str:
        """Obtain Jamf Protect access token using client_id + password."""
        token_url = self._get_full_url(PROTECT_API_ENDPOINTS["auth"])
        payload = {"client_id": self.client_api_id, "password": self.client_api_secret}
        self._log("info", f"Requesting Jamf Protect token at: {token_url}")
        resp = self.session.post(token_url, json=payload, timeout=30)
        if resp.status_code != 200:
            raise JamfError(
                f"Jamf Protect token request failed: HTTP {resp.status_code} - {resp.text}"
            )
        data = resp.json()
        token = data.get("access_token")
        expires_in = int(data.get("expires_in", 0))
        if not token:
            raise JamfError(f"Jamf Protect token response missing access_token: {data}")
        self.access_token = token
        self.token_expiration_epoch = int(time.time()) + max(expires_in - 1, 0)
        return token

    def _ensure_token(self) -> None:
        if not self.access_token or int(time.time()) >= self.token_expiration_epoch:
            self.get_access_token()

    def graphql(self, query: str, variables: Optional[dict] = None) -> dict:
        """Call Jamf Protect GraphQL endpoint.

        Jamf Protect expects Authorization header to be the raw token (no 'Bearer ').
        """
        self._ensure_token()
        if variables is None:
            variables = {}
        url = self._get_full_url("graphQL")
        headers = {
            "Authorization": self.access_token or "",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload = {"query": query, "variables": variables}
        self._log("info", f"POST {url} (GraphQL)")
        self._log("info", f"Payload: {payload}")
        resp = self.session.post(url, json=payload, headers=headers, timeout=60)
        try:
            data = resp.json()
            self._log("info", f"Response: {data}")
        except Exception:
            data = {"raw": resp.text}
        if resp.status_code != 200:
            raise JamfError(f"Jamf Protect GraphQL HTTP {resp.status_code}: {resp.text}")
        # GraphQL may include 'errors' while still being HTTP 200; caller can decide handling.
        return data

    def test_connectivity(self) -> bool:
        """Test Jamf Protect connectivity by obtaining an access token.
        """
        self._log("info", "Testing Jamf Protect connectivity (token only)...")
        self.get_access_token()
        return True

    def create_prevent_list(
        self,
        name: str,
        description: str | None,
        prevent_type: str,
        values: list[str],
        tags: list[str] | None = None,
    ) -> dict:
        """Create a Jamf Protect prevent list and add items in a single mutation."""
        if not name or not name.strip():
            raise JamfError("Prevent list name is required")
        if not values:
            raise JamfError("At least one value must be provided for the prevent list")
        if not tags:
            raise JamfError("At least one tag must be provided for the prevent list")

        prevent_type = PROTECT_PREVENT_TYPE_MAP.get(prevent_type)
        if not prevent_type:
            raise JamfError(f"Unsupported Prevent Type: {prevent_type}")

        # Helper to escape GraphQL string values
        def _gql_escape(s: str) -> str:
            return (s or "").replace("\\", "\\\\").replace('"', '\\"')

        name_esc = _gql_escape(name)
        desc_esc = _gql_escape(description or "")
        values_list = ",".join([f'"{_gql_escape(v)}"' for v in values])
        tags_list = ",".join([f'"{_gql_escape(t)}"' for t in (tags or [])])

        mutation_inline_list = (
            "mutation { "
            f'createPreventList(input: {{ name:"{name_esc}", description:"{desc_esc}", '
            f"type: {prevent_type}, list:[{values_list}], tags:[{tags_list}] }}) "
            "{ id name description type list tags } }"
        )
        try:
            resp = self.graphql(mutation_inline_list)
            self._log("info", f"Response: {resp}")
            self._log("info", f"Mutation: {mutation_inline_list}")
            errors = resp.get("errors") if isinstance(resp, dict) else None
        except JamfError:
            # If HTTP error, surface immediately
            raise

        if errors:
            raise JamfError(f"Jamf Protect did not return a prevent list ID: {resp}")

        return resp

    def update_prevent_list(
        self,
        name: str,
        description: str | None,
        prevent_type: str,
        values: list[str],
        tags: list[str] | None = None,
        id: str | None = None,
    ) -> dict:
        """Update a Jamf Protect prevent list and add items in a single mutation."""
        if not name or not name.strip():
            raise JamfError("Prevent list name is required")
        if not values:
            raise JamfError("At least one value must be provided for the prevent list")
        if not tags:
            raise JamfError("At least one tag must be provided for the prevent list")
        if not prevent_type:
            raise JamfError(f"Unsupported Prevent Type: {prevent_type}")

        # Helper to escape GraphQL string values
        def _gql_escape(s: str) -> str:
            return (s or "").replace("\\", "\\\\").replace('"', '\\"')

        name_esc = _gql_escape(name)
        desc_esc = _gql_escape(description or "")
        values_list = ",".join([f'"{_gql_escape(v)}"' for v in values])
        tags_list = ",".join([f'"{_gql_escape(t)}"' for t in (tags or [])])

        mutation_inline_list = (
            "mutation { "
            f'updatePreventList(input: {{ name:"{name_esc}", description:"{desc_esc}", '
            f"type: {prevent_type}, list:[{values_list}], tags:[{tags_list}] }} id: {id}) "
            "{ id name description type list tags } }"
        )
        try:
            resp = self.graphql(mutation_inline_list)
            self._log("info", f"Response: {resp}")
            self._log("info", f"Mutation: {mutation_inline_list}")
            errors = resp.get("errors") if isinstance(resp, dict) else None
        except JamfError:
            # If HTTP error, surface immediately
            raise

        if errors:
            raise JamfError(f"Jamf Protect did not return a prevent list ID: {resp}")

        return resp

    def list_prevent_lists(self) -> dict:
        """List all Jamf Protect prevent lists."""
        mutation_inline_list = (
            "query {listPreventLists {items {id name description type list tags}}}"
        )

        try:
            resp = self.graphql(mutation_inline_list)
            self._log("info", f"Response: {resp}")
            result = resp.get("data", {}).get("listPreventLists", {}).get("items", [])
            return result
        except JamfError:
            raise
