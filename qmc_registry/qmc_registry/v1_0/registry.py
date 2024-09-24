import logging
import re
from typing import Optional, Pattern, Sequence
import json
from aries_cloudagent.config.injection_context import InjectionContext # type: ignore
from aries_cloudagent.core.profile import Profile # type: ignore
from aries_cloudagent.anoncreds.base import BaseAnonCredsResolver, BaseAnonCredsRegistrar # type: ignore
from aries_cloudagent.cache.base import BaseCache
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
from aries_cloudagent.anoncreds.models.anoncreds_revocation import ( # type: ignore
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevRegDefValue,
)

from aries_cloudagent.anoncreds.models.anoncreds_schema import AnonCredsSchema, GetSchemaResult, SchemaResult  # type: ignore
from aries_cloudagent.anoncreds.issuer import CATEGORY_CRED_DEF, AnonCredsIssuer, AnonCredsIssuerError # type: ignore
import requests
from .config import get_config

LOGGER = logging.getLogger(__name__)

# Defaults
DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_SIGNATURE_TYPE = "CL"

DID = "did:qmc:"

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

    @staticmethod
    def make_rev_reg_def_id(rev_reg_def: RevRegDef) -> str:
        """Derive the ID for a revocation registry definition."""
        return (
            f"{rev_reg_def.issuer_id}:4:{rev_reg_def.cred_def_id[8:]}:"
            f"{rev_reg_def.type}:{rev_reg_def.tag}"
        )

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        LOGGER.info("Get schema. ID_SCHEMA: {schema_id}")
        get_shema_url = f'{get_config(profile.settings).host + ":" + str(get_config(profile.settings).port)}/schema/{schema_id[8:]}'
        responce = requests.get(get_shema_url)
        responce_body = responce.json()

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
        
        get_shema_url = f'{get_config(profile.settings).host+ ":" + str(get_config(profile.settings).port)}/schema'
        schema_id = self.make_schema_id(schema)

        LOGGER.info("Register schema. ID_SCHEMA: {schema_id}")

        data = {
            "schema_id": schema_id[8:],
            "issuer_id": schema.issuer_id[8:],
            "attr_names": schema.attr_names,
            "name": schema.name,
            "version": schema.version,
            "ver": "1.0"
        }
        responce = requests.post(url=get_shema_url, json={"schema": data})

        if responce.status_code != 200:
            raise AnonCredsRegistrationError("Failed to register schema") 

        response_body = responce.json()

        if response_body["error"] == True:
            raise AnonCredsRegistrationError(f"Failed to register schema. {response_body["message_error"]}") 

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
        LOGGER.info("Get credential definition. ID_cred_def: {credential_definition_id}")
        get_cred_def_url = f'{get_config(profile.settings).host+ ":" +str(get_config(profile.settings).port)}/credential-definition/{credential_definition_id[8:]}'
        responce = requests.get(get_cred_def_url)
        responce_body = responce.json()

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
        options = options or {}
        cred_def_id = self.make_cred_def_id(schema, credential_definition)

        LOGGER.info("Register credential definition. ID_cred_def: {cred_def_id}")

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

        qmc_cred_def = {
            "cred_def_id": cred_def_id[8:],
            "schema_id": str(schema.schema_id[8:]),
            "tag": credential_definition.tag,
            "ttype": credential_definition.type,
            "value": credential_definition.value.serialize(),
            "ver": "1.0",
        }
        
        get_shema_url = f'{get_config(profile.settings).host+ ":" +str(get_config(profile.settings).port)}/credential-definition'
        responce = requests.post(url=get_shema_url, json={"cred_def": qmc_cred_def})

        if responce.status_code != 200:
            raise AnonCredsRegistrationError("Failed to register credential definition.") 

        response_body = responce.json()
        if response_body["error"] == True:
            raise AnonCredsRegistrationError(f"Failed to register credential definition. {response_body["message_error"]}") 

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
        LOGGER.info("Get revocation registry definition. Id_rev_reg_def: {revocation_registry_id}")
        get_rev_reg_def_url = f'{get_config(profile.settings).host+ ":" +str(get_config(profile.settings).port)}/credential-definition/{revocation_registry_id[8:]}'
        responce = requests.get(get_rev_reg_def_url)
        responce_body = responce.json()

        if responce_body["revocation-registry-definition"] == {}:
            raise AnonCredsObjectNotFound(
                        f"Revocation registry definition not found: {revocation_registry_id}"
                )

        rev_reg_def = responce_body["revocation-registry-definition"]

        rev_reg_def_value = RevRegDefValue.deserialize(rev_reg_def["value"])
        anoncreds_rev_reg_def = RevRegDef(
            issuer_id=DID+rev_reg_def["rev_reg_def_id"].split(":")[0],
            cred_def_id=rev_reg_def["cred_def_id"],
            type=rev_reg_def["rev_reg_def_type"],
            value=rev_reg_def_value,
            tag=rev_reg_def["tag"],
        )
        result = GetRevRegDefResult(
            revocation_registry=anoncreds_rev_reg_def,
            revocation_registry_id=rev_reg_def["rev_reg_def_id"],
            resolution_metadata={},
            revocation_registry_metadata={},
        )

        return result

    async def register_revocation_registry_definition(
            self,
            profile: Profile,
            revocation_registry_definition: RevRegDef,
            options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        
        options = options or {}
        rev_reg_def_id = self.make_rev_reg_def_id(revocation_registry_definition)
        
        LOGGER.info("Register revocation registry definition. ID_rev_reg_def: {rev_reg_def_id}")

        qmc_rev_reg_def = {
            "rev_reg_def_id": rev_reg_def_id[8:],
            "cred_def_id": revocation_registry_definition.cred_def_id[8:],
            "rev_reg_def_type": revocation_registry_definition.type,
            "tag": revocation_registry_definition.tag,
            "value": {
                "issuance_type": "ISSUANCE_BY_DEFAULT",
                "public_keys": revocation_registry_definition.value.public_keys,
                "max_cred_num": revocation_registry_definition.value.max_cred_num,
                "tails_location": revocation_registry_definition.value.tails_location,
                "tails_hash": revocation_registry_definition.value.tails_hash
            },
            "ver": "1.0"
        }
        
        registry_rev_reg_def_url = f'{get_config(profile.settings).host+ ":" +str(get_config(profile.settings).port)}/revocation-registry-definition'
        responce = requests.post(url=registry_rev_reg_def_url, json={"rev_reg_def": qmc_rev_reg_def})

        if responce.status_code != 200:
            raise AnonCredsRegistrationError("Failed to register revocation registry definition.") 

        response_body = responce.json()
        if response_body["error"] == True:
            raise AnonCredsRegistrationError(f"Failed to register revocation registry definition. {response_body["message_error"]}") 

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=rev_reg_def_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "txn": None,
            },
            revocation_registry_definition_metadata={},
        )

    async def get_revocation_list(
            self, profile: Profile, revocation_registry_id: str, timestamp: int
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        LOGGER.info("Get revocation list. Id_rev_reg_def: {revocation_registry_id}")
        raise NotImplementedError()

    async def register_revocation_list(
            self,
            profile: Profile,
            rev_reg_def: RevRegDef,
            rev_list: RevList,
            options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        LOGGER.info("Register revocation list. Id_rev_reg_def: {rev_reg_def}")
        print("Register a revocation list on the registry.")
        print("REV_RED_DEF")
        print(rev_reg_def)        
        print("REV_LIST")
        print(rev_list)

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