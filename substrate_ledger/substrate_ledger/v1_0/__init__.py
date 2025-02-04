from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.ledger.base import BaseLedger
from aries_cloudagent.config.injection_context import InjectionContext
from .config import get_config

from .substrate_ledger import SubstrateLedger

async def setup(context: InjectionContext):
    url = get_config(context.settings).url
    context.injector.bind_instance(BaseLedger, SubstrateLedger(url=url))