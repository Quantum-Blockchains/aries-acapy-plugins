from aries_cloudagent.ledger.base import BaseLedger
from substrateinterface import SubstrateInterface, Keypair
import logging
from aries_cloudagent.ledger.error import LedgerError
from typing import Optional, Dict, Any
from .config import get_config
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.wallet.base import BaseWallet, DIDInfo

LOGGER = logging.getLogger(__name__)

class SubstrateLedger(BaseLedger):
    def __init__(self, url):
        LOGGER.info("init substrate ledger")
        self.substrate = SubstrateInterface(url=url)
        self.taa_cache = None
        # self.profile = profile
        # self.keypair = keypair or Keypair.create_from_mnemonic(config.config['agent']['keypair_mnemonic'])

    @property
    def read_only(self) -> bool:
        """Return whether the ledger is read-only."""
        return False  # Adjust based on your implementation

    async def get_did(self, did: str) -> Dict[str, Any]:
        """Fetch DID from Substrate ledger."""
        # Implement logic to fetch DID from Substrate
        raise NotImplementedError("Substrate ledger does not support fetching DIDs yet.")

    async def register_did(self, did: str, verkey: str, alias: Optional[str] = None) -> bool:
        """Register DID on Substrate ledger."""
        # Implement logic to register DID on Substrate
        raise NotImplementedError("Substrate ledger does not support registering DIDs yet.")

    async def update_endpoint_for_did(self, did: str, endpoint: str) -> bool:
        """Update endpoint for DID on Substrate ledger."""
        # Implement logic to update endpoint for DID on Substrate
        raise NotImplementedError("Substrate ledger does not support updating endpoints yet.")

    async def _create_credential_definition_request(self, *args, **kwargs):
        """Create a credential definition request."""
        raise NotImplementedError("Substrate ledger does not support credential definitions.")

    async def _create_revoc_reg_def_request(self, *args, **kwargs):
        """Create a revocation registry definition request."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def _create_schema_request(self, *args, **kwargs):
        """Create a schema request."""
        raise NotImplementedError("Substrate ledger does not support schemas.")

    async def accept_txn_author_agreement(self, *args, **kwargs):
        """Accept the transaction author agreement."""
        raise NotImplementedError("Substrate ledger does not support transaction author agreements.")

    async def fetch_schema_by_id(self, *args, **kwargs):
        """Fetch a schema by ID."""
        raise NotImplementedError("Substrate ledger does not support schemas.")

    async def fetch_schema_by_seq_no(self, *args, **kwargs):
        """Fetch a schema by sequence number."""
        raise NotImplementedError("Substrate ledger does not support schemas.")

    async def fetch_txn_author_agreement(self, *args, **kwargs):
        """Fetch the transaction author agreement."""
        # public_info = await self.get_wallet_public_did()
        # public_did = public_info.did if public_info else None
        aml_found = {
            "aml": {
                "additionalProp1": "string",
                "additionalProp2": "string",
                "additionalProp3": "string"
            },
            "amlContext": "string",
            "version": "string"
        }
        taa_found = {
            "digest": "string",
            "text": "string",
            "version": "string"
        }
        taa_required = True
        return {
            "aml_record": aml_found,
            "taa_record": taa_found,
            "taa_required": taa_required,
        }

    async def get_all_endpoints_for_did(self, *args, **kwargs):
        """Get all endpoints for a DID."""
        raise NotImplementedError("Substrate ledger does not support endpoints for DIDs.")

    async def get_credential_definition(self, *args, **kwargs):
        """Get a credential definition."""
        raise NotImplementedError("Substrate ledger does not support credential definitions.")

    async def get_endpoint_for_did(self, *args, **kwargs):
        """Get the endpoint for a DID."""
        raise NotImplementedError("Substrate ledger does not support endpoints for DIDs.")

    async def get_key_for_did(self, *args, **kwargs):
        """Get the key for a DID."""
        raise NotImplementedError("Substrate ledger does not support keys for DIDs.")

    async def get_nym_role(self, *args, **kwargs):
        """Get the role for a NYM."""
        raise NotImplementedError("Substrate ledger does not support NYM roles.")

    async def get_revoc_reg_def(self, *args, **kwargs):
        """Get a revocation registry definition."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def get_revoc_reg_delta(self, *args, **kwargs):
        """Get a revocation registry delta."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def get_revoc_reg_entry(self, *args, **kwargs):
        """Get a revocation registry entry."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def get_schema(self, *args, **kwargs):
        """Get a schema."""
        raise NotImplementedError("Substrate ledger does not support schemas.")

    async def get_txn_author_agreement(self, reload: bool = False) -> dict:
        """Get the transaction author agreement."""
        if not self.taa_cache or reload:
            self.taa_cache = await self.fetch_txn_author_agreement
        return self.taa_cache

    async def get_wallet_public_did(self, *args, **kwargs) -> DIDInfo:
        """Get the public DID from the wallet."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            return await wallet.get_public_did()

    async def nym_to_did(self, *args, **kwargs):
        """Convert a NYM to a DID."""
        raise NotImplementedError("Substrate ledger does not support NYM to DID conversion.")

    async def register_nym(self, *args, **kwargs):
        """Register a NYM."""
        raise NotImplementedError("Substrate ledger does not support NYM registration.")

    async def rotate_public_did_keypair(self, *args, **kwargs):
        """Rotate the public DID keypair."""
        raise NotImplementedError("Substrate ledger does not support key rotation.")

    async def send_revoc_reg_def(self, *args, **kwargs):
        """Send a revocation registry definition."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def send_revoc_reg_entry(self, *args, **kwargs):
        """Send a revocation registry entry."""
        raise NotImplementedError("Substrate ledger does not support revocation registries.")

    async def txn_endorse(self, *args, **kwargs):
        """Endorse a transaction."""
        raise NotImplementedError("Substrate ledger does not support transaction endorsement.")

    async def txn_submit(self, *args, **kwargs):
        """Submit a transaction."""
        raise NotImplementedError("Substrate ledger does not support transaction submission.")
    
    async def get_latest_txn_author_acceptance(self):
        raise NotImplementedError("Substrate ledger does not support.")
    
    async def is_ledger_read_only(self) -> bool:
        raise NotImplementedError("Substrate ledger does not support.")