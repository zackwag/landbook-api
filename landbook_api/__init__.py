"""Unofficial Python client for the Landbook (Netprisma/Landecia) cloud API.

Covers REST auth/device discovery/TSL model fetch and the WebSocket/TLS MQTT
pub/sub channel used for real-time device control and state.
"""

from .api import (
    LandbookAPIError,
    LandbookAuthError,
    async_get_device_attributes,
    async_get_device_list,
    async_get_tsl,
    async_login,
    async_refresh_token,
    get_device_attributes,
    get_device_list,
    get_tsl,
    login,
    refresh_token,
)
from .const import DEFAULT_REGION, REGIONS
from .mqtt_client import LandbookMQTTClient

__version__ = "0.7.1"  # x-release-please-version

__all__ = [
    "DEFAULT_REGION",
    "REGIONS",
    "LandbookAPIError",
    "LandbookAuthError",
    "LandbookMQTTClient",
    "async_get_device_attributes",
    "async_get_device_list",
    "async_get_tsl",
    "async_login",
    "async_refresh_token",
    "get_device_attributes",
    "get_device_list",
    "get_tsl",
    "login",
    "refresh_token",
]
