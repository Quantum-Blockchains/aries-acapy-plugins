import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.anoncreds.registry import AnonCredsRegistry
from .registry import QmcRegistry
from acapy_agent.multitenant.admin.routes import (
    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP,
)

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Set up default resolvers."""
    registry = context.inject_or(AnonCredsRegistry)
    if not registry:
        LOGGER.error("No AnonCredsRegistry instance found in context!!!")
        return
    qmc_registry = QmcRegistry()
    await qmc_registry.setup(context)
    registry.register(qmc_registry)

    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP["qmc-registry"] = (
        "qmc_registry"
    )
