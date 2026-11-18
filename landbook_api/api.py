"""Landbook API client — auth, device discovery, TSL model fetch."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .const import (
    APP_ID,
    APP_SYSTEM_TYPE,
    APP_VERSION,
    DEFAULT_REGION,
    REGIONS,
)


class LandbookAuthError(Exception):
    """Raised when the server rejects credentials or a refresh token."""


class LandbookAPIError(Exception):
    """Raised when an API call fails or the server rejects a request."""


def _region_cfg(region: str) -> dict:
    return REGIONS.get(region, REGIONS[DEFAULT_REGION])


def _encrypt_password(password: str) -> tuple[str, str]:
    """Return (pwd_b64, rand) — AES-128-CBC, matches the Landbook app logic."""
    rand = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    md5_full = hashlib.md5(rand.encode()).hexdigest().upper()
    hash_random = md5_full[8:24]
    iv = hash_random[8:16] + hash_random[0:8]

    cipher = AES.new(hash_random.encode(), AES.MODE_CBC, iv.encode())
    encrypted = cipher.encrypt(pad(password.encode(), AES.block_size))
    pwd = base64.b64encode(encrypted).decode()
    return pwd, rand


def _request(
    region: str,
    path: str,
    *,
    what: str | None = None,
    method: str = "GET",
    token: str | None = None,
    query: dict | None = None,
    form: dict | None = None,
    rejected_error: type[Exception] = LandbookAPIError,
) -> Any:
    """Call a Landbook REST endpoint and return its `data` field.

    A transport or parse failure raises LandbookAPIError; a response the
    server rejected (non-200 `code`, or no `data`) raises `rejected_error`
    with the server's `msg` in the text. `what` names the call in error
    messages and defaults to `path`.
    """
    what = what or path
    url = _region_cfg(region)["api_base"] + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {
        "appId": APP_ID,
        "appVersion": APP_VERSION,
        "appSystemType": APP_SYSTEM_TYPE,
        "Accept": "application/json",
    }
    if token is not None:
        headers["Authorization"] = token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        resp = json.loads(urllib.request.urlopen(req).read())
    except urllib.error.HTTPError as exc:
        resp = _rejection_envelope(exc)
        if resp is None:
            raise LandbookAPIError(f"{what} request failed: {exc}") from exc
    except Exception as exc:
        raise LandbookAPIError(f"{what} request failed: {exc}") from exc

    if not isinstance(resp, dict) or resp.get("code") != 200 or "data" not in resp:
        msg = resp.get("msg", "unknown error") if isinstance(resp, dict) else resp
        raise rejected_error(f"{what} rejected: {msg}")
    return resp["data"]


def _rejection_envelope(exc: urllib.error.HTTPError) -> dict | None:
    """The API's own JSON envelope from a 4xx response, so its rejection msg
    is judged like any other. A 5xx, a gateway error page or an unreadable
    body is a transport failure instead, never a rejection."""
    if not 400 <= exc.code < 500:
        return None
    try:
        resp = json.loads(exc.read())
    except (OSError, ValueError):
        return None
    return resp if isinstance(resp, dict) and "code" in resp else None


def _token_pair(data: Any, what: str) -> tuple[str, str]:
    """(access_token, refresh_token) from a login or refresh response."""
    try:
        return data["accessToken"]["token"], data["refreshToken"]["token"]
    except (KeyError, TypeError) as exc:
        raise LandbookAPIError(f"{what} response not understood: {exc!r}") from exc


def login(email: str, password: str, region: str = DEFAULT_REGION) -> tuple[str, str, str]:
    """Authenticate and return (bearer_token, uid, refresh_token).

    The access token is only valid for 2 hours; the refresh token (returned
    alongside it) is what actually renews the session and is valid for 30
    days. Both must be persisted — see refresh_token() below.
    """
    cfg = _region_cfg(region)
    pwd, rand = _encrypt_password(password)
    sig = hashlib.sha256((email + pwd + rand + cfg["app_domain_key"]).encode()).hexdigest()

    data = _request(
        region,
        "/v2/enduser/enduserapi/emailPwdLogin",
        what="Login",
        method="POST",
        form={
            "email": email,
            "pwd": pwd,
            "random": rand,
            "userDomain": cfg["user_domain"],
            "signature": sig,
        },
        rejected_error=LandbookAuthError,
    )

    bearer_token, refresh_token_value = _token_pair(data, "Login")
    try:
        jwt_payload = bearer_token.replace("Bearer ", "").split(".")[1]
        uid: str = json.loads(
            base64.urlsafe_b64decode(jwt_payload + "=" * (-len(jwt_payload) % 4))
        )["uid"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LandbookAPIError(f"Login response not understood: {exc!r}") from exc
    return bearer_token, uid, refresh_token_value


def refresh_token(
    bearer_token: str, refresh_token_value: str, region: str = DEFAULT_REGION
) -> tuple[str, str]:
    """Exchange the refresh token for a new (access_token, refresh_token) pair.

    The API requires BOTH the current access token as the Authorization
    header AND the full refresh token (including its "Bearer " prefix) as a
    form-encoded `refreshToken` body field — sending only one or the other
    is rejected. The refresh token itself rotates on every successful call,
    so the new one returned here must be persisted too, not just the access
    token.
    """
    data = _request(
        region,
        "/v2/enduser/enduserapi/refreshToken",
        what="Token refresh",
        method="PUT",
        token=bearer_token,
        form={"refreshToken": refresh_token_value},
        rejected_error=LandbookAuthError,
    )
    return _token_pair(data, "Token refresh")


def get_device_list(bearer_token: str, region: str = DEFAULT_REGION) -> list[dict]:
    data = _request(
        region,
        "/v2/binding/enduserapi/userDeviceList",
        token=bearer_token,
        query={"page": 1, "pageSize": 50},
    )
    return data.get("list", [])


def get_tsl(bearer_token: str, pk: str, region: str = DEFAULT_REGION) -> list[dict]:
    """Return the product's writable properties, in display order."""
    data = _request(
        region, "/v2/binding/enduserapi/productTSL", token=bearer_token, query={"pk": pk}
    )
    properties = [
        p
        for p in data.get("properties", [])
        if "W" in p.get("subType", "") and p["type"] == "PROPERTY"
    ]
    properties.sort(key=lambda p: p.get("sort", 0))
    return properties


def get_device_attributes(
    bearer_token: str, pk: str, dk: str, region: str = DEFAULT_REGION
) -> dict:
    return _request(
        region,
        "/v2/binding/enduserapi/getDeviceBusinessAttributes",
        token=bearer_token,
        query={"pk": pk, "dk": dk},
    )


async def async_login(
    email: str, password: str, region: str = DEFAULT_REGION
) -> tuple[str, str, str]:
    return await asyncio.to_thread(login, email, password, region)


async def async_refresh_token(
    bearer_token: str, refresh_token_value: str, region: str = DEFAULT_REGION
) -> tuple[str, str]:
    return await asyncio.to_thread(refresh_token, bearer_token, refresh_token_value, region)


async def async_get_device_list(bearer_token: str, region: str = DEFAULT_REGION) -> list[dict]:
    return await asyncio.to_thread(get_device_list, bearer_token, region)


async def async_get_tsl(bearer_token: str, pk: str, region: str = DEFAULT_REGION) -> list[dict]:
    return await asyncio.to_thread(get_tsl, bearer_token, pk, region)


async def async_get_device_attributes(
    bearer_token: str, pk: str, dk: str, region: str = DEFAULT_REGION
) -> dict:
    return await asyncio.to_thread(get_device_attributes, bearer_token, pk, dk, region)
