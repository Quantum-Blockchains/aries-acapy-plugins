"""Configuration classes for multitenant_provider."""

import logging
from typing import Any, Mapping

from mergedeep import merge
from pydantic import BaseModel

LOGGER = logging.getLogger(__name__)


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class BasicMessageStorageConfig(BaseModel):
    """Configuration for the basicmessage_storage."""

    host: str = "http://127.0.0.1"
    port: int = 5002

    class Config:
        """Inner class for configuration."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        # consider this for local development only...
        return cls()


def process_config_dict(config_dict: dict) -> dict:
    """Remove any keys that are not in the config class."""
    print(1)
    _filter = BasicMessageStorageConfig.default().model_dump().keys()
    print(2)
    for key, value in config_dict.items():
        print(3)
        if key in _filter:
            print(4)
            config_dict[key] = value
    print(5)
    return config_dict


def get_config(settings: Mapping[str, Any]) -> BasicMessageStorageConfig:
    """Retrieve configuration from settings."""
    try:
        LOGGER.info(
            "Constructing config from: %s",
            settings.get("plugin_config", {}).get("qmc_registry"),
        )
        global_plugin_config_dict = settings.get("plugin_config", {}).get(
            "qmc_registry", {}
        )
        tenant_plugin_config_dict = settings.get("qmc_registry", {})
        LOGGER.info("Retrieved (global): %s", global_plugin_config_dict)
        LOGGER.info("Retrieved (tenant)): %s", tenant_plugin_config_dict)
        global_plugin_config_dict = process_config_dict(global_plugin_config_dict)
        tenant_plugin_config_dict = process_config_dict(tenant_plugin_config_dict)
        LOGGER.info("Parsed (global): %s", global_plugin_config_dict)
        LOGGER.info("Parsed (tenant): %s", tenant_plugin_config_dict)
        default_config = BasicMessageStorageConfig.default().model_dump()
        LOGGER.info("Default Config: %s", default_config)
        config_dict = merge(
            {}, default_config, global_plugin_config_dict, tenant_plugin_config_dict
        )
        LOGGER.info("Merged: %s", config_dict)
        config = BasicMessageStorageConfig(**config_dict)
    except KeyError:
        LOGGER.warning("Using default configuration")
        config = BasicMessageStorageConfig.default()

    LOGGER.info("Returning config: %s", config.model_dump_json(indent=2))
    LOGGER.info(
        "Returning config(aliases): %s", config.model_dump_json(by_alias=True, indent=2)
    )
    return config