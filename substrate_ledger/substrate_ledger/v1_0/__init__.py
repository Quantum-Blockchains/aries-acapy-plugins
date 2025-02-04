from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.ledger.base import BaseLedger
from aries_cloudagent.config.injection_context import InjectionContext

from .substrate_ledger import SubstrateLedger

async def setup(context: InjectionContext):
    registry = context.inject(PluginRegistry)
    registry.register_plugin("substrate_plugin", SubstratePlugin())

class SubstratePlugin:
    """Substrate Plugin for ACA-Py."""

    def __init__(self):
        self.name = "substrate_plugin"

    async def register_ledger(self, context: InjectionContext):
        """Register Substrate ledger."""
        ledger = SubstrateLedger()
        context.injector.bind_instance(BaseLedger, ledger)