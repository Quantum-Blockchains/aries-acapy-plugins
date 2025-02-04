from aries_cloudagent.ledger.base import BaseLedger
from substrateinterface import SubstrateInterface, Keypair
import logging

LOGGER = logging.getLogger(__name__)

class SubstrateLedger(BaseLedger):
    def __init__(self):
        LOGGER.info("init substrate ledger")
        self.substrate = SubstrateInterface(url="ws://localhost:9944")
        # self.keypair = keypair or Keypair.create_from_mnemonic(config.config['agent']['keypair_mnemonic'])