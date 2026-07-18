"""Protocol constants for the Landbook (Netprisma/Landecia) cloud API."""

APP_ID = "584"
APP_VERSION = "3.6.0"
APP_SYSTEM_TYPE = "ios"

MQTT_PORT = 8443
MQTT_WS_PATH = "/ws/v2"
MQTT_KEEPALIVE = 40

# Region definitions — sourced from ad0.java (i=0 CN, i=1 EU, i=2 US)
REGIONS: dict[str, dict] = {
    "us": {
        "label": "United States",
        "api_base": "https://iot-api.quectelus.com",
        "mqtt_host": "iot-south.landecia.com",
        "user_domain": "U.SP.8589934603",
        "app_domain_key": "pUTp5goB1bLinprRQMmK3EPiiuPiGrJtKUNptWRXVmP",
    },
    "eu": {
        "label": "Europe",
        "api_base": "https://iot-api.quecteleu.com",
        "mqtt_host": "iot-south.quecteleu.com",
        "user_domain": "E.SP.4294967410",
        "app_domain_key": "3aRNUwWahjyANa7WfBK2wCCkxCexB6nXxKJwXxfePvzf",
    },
    "cn": {
        "label": "China",
        "api_base": "https://iot-gateway.quectel.com",
        "mqtt_host": "iot-south.quectelcn.com",
        "user_domain": "C.DM.5903.1",
        "app_domain_key": "EufftRJSuWuVY7c6txzGifV9bJcfXHAFa7hXY5doXSn7",
    },
}

DEFAULT_REGION = "us"
