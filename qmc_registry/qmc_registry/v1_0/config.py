# """Configuration classes for multitenant_provider."""

# import logging
# from typing import Any, Mapping

# from mergedeep import merge
# from pydantic import BaseModel

# LOGGER = logging.getLogger(__name__)


# def _alias_generator(key: str) -> str:
#     return key.replace("_", "-")


# class BasicMessageStorageConfig(BaseModel):
#     """Configuration for the basicmessage_storage."""

#     url: str = "ws://localhost:9944"

#     class Config:
#         """Inner class for configuration."""

#         alias_generator = _alias_generator
#         populate_by_name = True

#     @classmethod
#     def default(cls):
#         """Return default configuration."""
#         # consider this for local development only...
#         return cls()


# def process_config_dict(config_dict: dict) -> dict:
#     """Remove any keys that are not in the config class."""
#     _filter = BasicMessageStorageConfig.default().model_dump().keys()
#     for key, value in config_dict.items():
#         if key in _filter:
#             config_dict[key] = value
#     return config_dict


# def get_config(settings: Mapping[str, Any]) -> BasicMessageStorageConfig:
#     """Retrieve configuration from settings."""
#     try:
#         LOGGER.debug(
#             "Constructing config from: %s",
#             settings.get("plugin_config", {}).get("qmc_registry"),
#         )
#         global_plugin_config_dict = settings.get("plugin_config", {}).get(
#             "qmc_registry", {}
#         )
#         tenant_plugin_config_dict = settings.get("qmc_registry", {})
#         LOGGER.debug("Retrieved (global): %s", global_plugin_config_dict)
#         LOGGER.debug("Retrieved (tenant)): %s", tenant_plugin_config_dict)
#         global_plugin_config_dict = process_config_dict(global_plugin_config_dict)
#         tenant_plugin_config_dict = process_config_dict(tenant_plugin_config_dict)
#         LOGGER.debug("Parsed (global): %s", global_plugin_config_dict)
#         LOGGER.debug("Parsed (tenant): %s", tenant_plugin_config_dict)
#         default_config = BasicMessageStorageConfig.default().model_dump()
#         LOGGER.debug("Default Config: %s", default_config)
#         config_dict = merge(
#             {}, default_config, global_plugin_config_dict, tenant_plugin_config_dict
#         )
#         LOGGER.debug("Merged: %s", config_dict)
#         config = BasicMessageStorageConfig(**config_dict)
#     except KeyError:
#         LOGGER.warning("Using default configuration")
#         config = BasicMessageStorageConfig.default()

#     LOGGER.debug("Returning config: %s", config.model_dump_json(indent=2))
#     LOGGER.debug(
#         "Returning config(aliases): %s", config.model_dump_json(by_alias=True, indent=2)
#     )
#     return config

"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for QMC_REGISTRY; use either "
            f"qmc_registry.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for OID4VCI Plugin."""

    url: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("qmc_registry")
        url = plugin_settings.get("url") or getenv("QMC_REGISTRY_URL")

        if not url:
            raise ConfigError("url", "QMC_REGISTRY_URL")

        return cls(url)