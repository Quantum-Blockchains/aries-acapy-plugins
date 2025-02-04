from aries_cloudagent.core.ledger.base import BaseLedger
from substrateinterface import SubstrateInterface, Keypair
import logging

LOGGER = logging.getLogger(__name__)

class SubstrateLedger(BaseLedger):
    def __init__(self, node_url: str, keypair: Keypair = None):
        LOGGER.info("init substrate ledger")
        self.substrate = SubstrateInterface(url=node_url)
        self.keypair = keypair or Keypair.create_from_mnemonic(config.config['agent']['keypair_mnemonic'])