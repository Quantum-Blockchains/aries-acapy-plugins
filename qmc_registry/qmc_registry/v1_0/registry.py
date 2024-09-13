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

from aries_cloudagent.anoncreds.base import (
    AnonCredsObjectAlreadyExists,
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    AnonCredsSchemaAlreadyExists,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import AnonCredsSchema, GetSchemaResult, SchemaResult

import requests

LOGGER = logging.getLogger(__name__)

URL = "http://192.168.222.253:5002"

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

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}:2:{schema.name}:{schema.version}"

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        LOGGER.info("Get schema ")
        get_shema_url = f'{URL}/schemas/{schema_id}'
        LOGGER.info(f'URL: {get_shema_url}')
        responce = requests.get(get_shema_url)
        responce_body = responce.json()

        LOGGER.info(f'RESPONCE: {responce_body}')

        anonscreds_schema = AnonCredsSchema(
            issuer_id="id1",
            attr_names=["1", "2"],
            name="shema1",
            version="1.0",
        )
        result = GetSchemaResult(
            schema=anonscreds_schema,
            schema_id="id1",
            resolution_metadata={"ledger_id": ""},
            schema_metadata={"seqNo": ""},
        )

        return result

    async def register_schema(
            self,
            profile: Profile,
            schema: AnonCredsSchema,
            options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        LOGGER.info("QMCREGISTRY : register schema ")

        LOGGER.info("Set schema ")
        get_shema_url = f'{URL}/schemas'
        LOGGER.info(f'URL: {get_shema_url}')

        schema_id = self.make_schema_id(schema)

        data = {
            "issuer_id": schema.issuer_id,
            "schema_id": schema_id,
            "attr_names": schema.attr_names,
            "version": schema.version,
            "name": schema.name,
        }
        print(data)
        responce = requests.post(url=get_shema_url, data=data)

        if responce.status_code != 200:
            raise AnonCredsRegistrationError("Failed to register schema") 

        response_body = responce.json()

        if response_body["error"] == True:
            raise AnonCredsRegistrationError(f"Failed to register schema. {response_body["message_error"]}") 

        LOGGER.info(f'FINISHED! extrinsic_hash: {response_body["extrinsic_hash"]}, block_hash: {response_body["block_hash"]}')

        return SchemaResult(
                job_id=None,
                schema_state=SchemaState(
                    state=SchemaState.STATE_FINISHED,
                    schema_id=schema_id,
                    schema=schema,
                ),
                registration_metadata={},
                schema_metadata={},
            )
    

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