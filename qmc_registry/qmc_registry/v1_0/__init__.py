import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.anoncreds.registry import AnonCredsRegistry
from .registry import QmcRegistry
from acapy_agent.multitenant.admin.routes import (
    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP,
)
# from .config import get_config
from .config import Config

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Set up default resolvers."""
    registry = context.inject_or(AnonCredsRegistry)
    if not registry:
        LOGGER.error("No AnonCredsRegistry instance found in context!!!")
        return
    try:
        config = Config.from_settings(context.settings)
        qmc_registry = QmcRegistry(
            url=config.url,
        )
    except Exception:
        LOGGER.exception("Unable to register admin server")
        raise
    # url = get_config(context.settings).url
    # qmc_registry = QmcRegistry(url=url)
    await qmc_registry.setup(context)
    registry.register(qmc_registry)

    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP["qmc-registry"] = (
        "qmc_registry"
    )
