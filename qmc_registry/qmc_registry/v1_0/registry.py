import logging
import re
from typing import Optional, Pattern, Sequence
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.anoncreds.base import BaseAnonCredsResolver, BaseAnonCredsRegistrar
from aries_cloudagent.anoncreds.models.anoncreds_cred_def import (
    CredDef,
    CredDefResult,
    GetCredDefResult,
)
from aries_cloudagent.anoncreds.models.anoncreds_revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import AnonCredsSchema, GetSchemaResult, SchemaResult

LOGGER = logging.getLogger(__name__)

class QmcRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    def __init__(self):
        """Initialize an instance.

        Args:
        TODO: update this docstring - Anoncreds-break.

        """
        self._supported_identifiers_regex = re.compile(r"^did:qmc.*$")

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return self._supported_identifiers_regex
        # TODO: fix regex (too general)

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered QMCRegistry")

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        LOGGER.info("QMCREGISTRY : get schema ")
        raise NotImplementedError()

    async def register_schema(
            self,
            profile: Profile,
            schema: AnonCredsSchema,
            options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        LOGGER.info("QMCREGISTRY : register schema ")
        raise NotImplementedError()

    async def get_credential_definition(
            self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        raise NotImplementedError()

    async def register_credential_definition(
            self,
            profile: Profile,
            schema: GetSchemaResult,
            credential_definition: CredDef,
            options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_registry_definition(
            self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        raise NotImplementedError()

    async def register_revocation_registry_definition(
            self,
            profile: Profile,
            revocation_registry_definition: RevRegDef,
            options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_list(
            self, profile: Profile, revocation_registry_id: str, timestamp: int
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        raise NotImplementedError()

    async def register_revocation_list(
            self,
            profile: Profile,
            rev_reg_def: RevRegDef,
            rev_list: RevList,
            options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        raise NotImplementedError()

    async def update_revocation_list(
            self,
            profile: Profile,
            rev_reg_def: RevRegDef,
            prev_list: RevList,
            curr_list: RevList,
            revoked: Sequence[int],
            options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        raise NotImplementedError()