import logging

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.provider import ClassProvider
from aries_cloudagent.anoncreds.registry import AnonCredsRegistry
from .registry import QmcRegistry
from aries_cloudagent.multitenant.admin.routes import (
    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP,
)

from .config import get_config

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Set up default resolvers."""
    LOGGER.info("ASIA UDALO SIE URA URA URA URA URA URA URA URA URA")
    registry = context.inject_or(AnonCredsRegistry)
    if not registry:
        LOGGER.error("No AnonCredsRegistry instance found in context!!!")
        return
    qmc_registry = QmcRegistry()
    # qmc_registry = ClassProvider(
    #     "qmc_registry.registry.QmcRegistry",
    #     # supported_identifiers=[],
    #     # method_name="did:indy",
    # ).provide(context.settings, context.injector)
    # await qmc_registry.setup(context)
    await qmc_registry.setup(context)
    registry.register(qmc_registry)

    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP["qmc-registry"] = (
        "qmc_registry"
    )