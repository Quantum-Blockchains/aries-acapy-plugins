from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.ledger.base import BaseLedger
from aries_cloudagent.config.injection_context import InjectionContext

from .substrate_ledger import SubstrateLedger

async def setup(context: InjectionContext):
    context.injector.bind_instance(BaseLedger, SubstrateLedger(context.settings["substrate_ledger"]["url"]))