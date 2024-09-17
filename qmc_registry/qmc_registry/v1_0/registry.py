import logging
import re
from typing import Optional, Pattern, Sequence
import json
from aries_cloudagent.config.injection_context import InjectionContext # type: ignore
from aries_cloudagent.core.profile import Profile # type: ignore
from aries_cloudagent.anoncreds.base import BaseAnonCredsResolver, BaseAnonCredsRegistrar # type: ignore
from aries_cloudagent.anoncreds.models.anoncreds_cred_def import (  # type: ignore
    CredDef,
    CredDefResult,
    GetCredDefResult,
)
from aries_cloudagent.anoncreds.models.anoncreds_revocation import (  # type: ignore
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)

from aries_cloudagent.anoncreds.base import (  # type: ignore
    AnonCredsObjectAlreadyExists,
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    AnonCredsSchemaAlreadyExists,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import (  # type: ignore
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from aries_cloudagent.anoncreds.models.anoncreds_cred_def import ( # type: ignore
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from aries_cloudagent.anoncreds.models.anoncreds_cred_def import ( # type: ignore
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import AnonCredsSchema, GetSchemaResult, SchemaResult  # type: ignore
from aries_cloudagent.anoncreds.issuer import CATEGORY_CRED_DEF, AnonCredsIssuer, AnonCredsIssuerError # type: ignore
import requests

LOGGER = logging.getLogger(__name__)

# Defaults
DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_SIGNATURE_TYPE = "CL"

DID = "did:qmc:"

URL = "http://192.168.65.253:5002"

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
    
    @staticmethod
    def make_cred_def_id(
        schema: GetSchemaResult,
        cred_def: CredDef,
    ) -> str:
        """Derive the ID for a credential definition."""
        signature_type = cred_def.type or DEFAULT_SIGNATURE_TYPE
        tag = cred_def.tag or DEFAULT_CRED_DEF_TAG

        return f"{cred_def.issuer_id}:3:{signature_type}:{tag}"

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        LOGGER.info("Get schema ")
        get_shema_url = f'{URL}/schema/{schema_id[8:]}'
        LOGGER.info(f'URL: {get_shema_url}')
        responce = requests.get(get_shema_url)
        responce_body = responce.json()

        LOGGER.info(f'RESPONCE: {responce_body}')

        if responce_body["schema"] == {}:
            raise AnonCredsObjectNotFound(
                        f"Schema not found: {schema_id}"
                    )

        anonscreds_schema = AnonCredsSchema(
            issuer_id=DID + responce_body["schema"]["issuer_id"],
            attr_names=responce_body["schema"]["attr_names"],
            name=responce_body["schema"]["name"],
            version=responce_body["schema"]["version"],
        )
        result = GetSchemaResult(
            schema=anonscreds_schema,
            schema_id=DID + responce_body["schema"]["schema_id"],
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
        get_shema_url = f'{URL}/schema'
        LOGGER.info(f'URL: {get_shema_url}')

        schema_id = self.make_schema_id(schema)

        data = {
            "issuer_id": schema.issuer_id[8:],
            "schema_id": schema_id[8:],
            "attr_names": schema.attr_names,
            "version": schema.version,
            "name": schema.name,
            "ver": "1.0"
        }
        print(data)
        responce = requests.post(url=get_shema_url, json={"schema": data})

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
        LOGGER.info("Get credential definition ")
        get_cred_def_url = f'{URL}/credential-definition/{credential_definition_id[8:]}'
        LOGGER.info(f'URL: {get_cred_def_url}')
        responce = requests.get(get_cred_def_url)
        responce_body = responce.json()

        LOGGER.info(f'RESPONCE: {responce_body}')

        if responce_body["credential-definition"] == {}:
            raise AnonCredsObjectNotFound(
                        f"Credential definition not found: {credential_definition_id}"
                )

        cred_def = responce_body["credential-definition"]

        cred_def_value = CredDefValue.deserialize(cred_def["value"])
        anoncreds_credential_definition = CredDef(
            issuer_id=DID+cred_def["id"].split(":")[0],
            schema_id=DID+cred_def["schemaId"],
            type=cred_def["type"],
            tag=cred_def["tag"],
            value=cred_def_value,
        )
        anoncreds_registry_get_credential_definition = GetCredDefResult(
            credential_definition=anoncreds_credential_definition,
            credential_definition_id=DID+cred_def["id"],
            resolution_metadata={},
            credential_definition_metadata={},
        )
        return anoncreds_registry_get_credential_definition

    async def register_credential_definition(
            self,
            profile: Profile,
            schema: GetSchemaResult,
            credential_definition: CredDef,
            options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        LOGGER.info("Register a credential definition ")
        options = options or {}
        cred_def_id = self.make_cred_def_id(schema, credential_definition)

        # Check if in wallet but not on ledger
        issuer = AnonCredsIssuer(profile)
        if await issuer.credential_definition_in_wallet(cred_def_id):
            try:
                await self.get_credential_definition(profile, cred_def_id)
            except AnonCredsObjectNotFound as err:
                raise AnonCredsRegistrationError(
                    f"Credential definition with id {cred_def_id} already "
                    "exists in wallet but not on the ledger"
                ) from err

        # Translate anoncreds object to indy object
        LOGGER.debug("Registering credential definition: %s", cred_def_id)
        qmc_cred_def = {
            "id": cred_def_id[8:],
            "schema_id": str(schema.schema_id[8:]),
            "tag": credential_definition.tag,
            "type": credential_definition.type,
            "value": credential_definition.value.serialize(),
            "ver": "1.0",
        }
        LOGGER.debug("Cred def value: %s", qmc_cred_def)

        LOGGER.info("Cred def value: %s", qmc_cred_def)
        
        get_shema_url = f'{URL}/credential-definition'
        LOGGER.info("Cred def url: %s", get_shema_url)
        print(qmc_cred_def)
        responce = requests.post(url=get_shema_url, json={"cred_def": qmc_cred_def})

        if responce.status_code != 200:
            raise AnonCredsRegistrationError("Failed to register credential definition.") 

        response_body = responce.json()
        LOGGER.info("Cred def url: %s", response_body)
        if response_body["error"] == True:
            raise AnonCredsRegistrationError(f"Failed to register credential definition. {response_body["message_error"]}") 

        LOGGER.info(f'FINISHED! extrinsic_hash: {response_body["extrinsic_hash"]}, block_hash: {response_body["block_hash"]}')

        return CredDefResult(
            job_id=None,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=cred_def_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={},
            credential_definition_metadata={},
        )

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