//! KMS schemas, typed dispatch, and delivery.

use super::{
    CallToolRequestParams, CallToolResult, Deserialize, InfisicalClient, JsonSchema,
    KMS_DECRYPT_TOOL, KMS_ENCRYPT_TOOL, KMS_KEYS_BULK_IMPORT_TOOL, KMS_KEYS_CREATE_TOOL,
    KMS_KEYS_DELETE_TOOL, KMS_KEYS_GET_BY_NAME_TOOL, KMS_KEYS_GET_TOOL, KMS_KEYS_LIST_TOOL,
    KMS_KEYS_UPDATE_TOOL, KMS_PRIVATE_KEY_REVEAL_TOOL, KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL,
    KMS_PUBLIC_KEY_GET_TOOL, KMS_SIGN_TOOL, KMS_SIGNING_ALGORITHMS_LIST_TOOL, KMS_VERIFY_TOOL,
    KmsBulkImportEntry, KmsBulkPrivateKey, KmsData, KmsDecryptedData, KmsKeyAlgorithm,
    KmsKeyChange, KmsKeyCreation, KmsKeyId, KmsKeyListRequest, KmsKeyMaterial, KmsKeyName,
    KmsKeyUsage, KmsPrivateKey, KmsSigningAlgorithm, MAX_KMS_BULK_KEYS, McpError, ProjectId,
    SecretDeliveryMode, SecretDisposition, SecretFilePlane, SecretFileReference, SecretValue,
    Serialize, SerializeStruct, Serializer, default_page_limit, delivered_result,
    deserialize_secret_input, invalid_input, page_request, parse_arguments, resolve_delivery,
    tool_result,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeyTargetInput {
    /// Opaque Infisical project identifier that must own the key.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// Canonical UUID identifying one exact KMS key.
    #[schemars(regex(
        pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ))]
    key_id: String,
}

impl KmsKeyTargetInput {
    fn into_parts(self) -> Result<(ProjectId, KmsKeyId), McpError> {
        Ok((
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            KmsKeyId::new(self.key_id).map_err(invalid_input)?,
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeysListInput {
    /// Opaque Infisical project identifier whose keys are listed.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// Zero-based upstream collection offset.
    #[serde(default)]
    #[schemars(range(min = 0, max = 100_000))]
    offset: u32,
    /// Maximum key records returned in this response.
    #[serde(default = "default_page_limit")]
    #[schemars(range(min = 1, max = 100))]
    limit: u16,
    /// Sort key names in descending rather than ascending order.
    #[serde(default)]
    descending: bool,
    /// Optional bounded server-side key-name search text.
    #[schemars(length(max = 256))]
    search: Option<String>,
}

impl KmsKeysListInput {
    fn into_request(self) -> Result<KmsKeyListRequest, McpError> {
        KmsKeyListRequest::new(
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            page_request(self.offset, self.limit)?,
            self.descending,
            self.search,
        )
        .map_err(invalid_input)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeyByNameInput {
    /// Opaque Infisical project identifier that must own the key.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// Canonical lowercase KMS key name.
    #[schemars(regex(pattern = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"), length(max = 32))]
    key_name: String,
}

impl KmsKeyByNameInput {
    fn into_parts(self) -> Result<(ProjectId, KmsKeyName), McpError> {
        Ok((
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            KmsKeyName::new(self.key_name).map_err(invalid_input)?,
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeyCreateInput {
    /// Opaque Infisical project identifier that will own the key.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// Canonical lowercase KMS key name.
    #[schemars(regex(pattern = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"), length(max = 32))]
    name: String,
    /// Optional non-secret operator description.
    #[schemars(length(max = 500))]
    description: Option<String>,
    /// Fixed cryptographic purpose for the key.
    key_usage: KmsKeyUsage,
    /// Exact algorithm compatible with the selected key usage.
    algorithm: KmsKeyAlgorithm,
    /// Must be true to acknowledge creation of persistent cryptographic material.
    confirm: bool,
}

impl KmsKeyCreateInput {
    fn into_parts(self) -> Result<(ProjectId, KmsKeyCreation, bool), McpError> {
        Ok((
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            KmsKeyCreation::new(
                KmsKeyName::new(self.name).map_err(invalid_input)?,
                self.description,
                self.key_usage,
                self.algorithm,
            )
            .map_err(invalid_input)?,
            self.confirm,
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeyUpdateInput {
    /// Exact project and key identifiers to update.
    target: KmsKeyTargetInput,
    /// Optional complete replacement key name.
    #[schemars(regex(pattern = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"), length(max = 32))]
    name: Option<String>,
    /// Optional complete replacement description; an empty string clears it.
    #[schemars(length(max = 500))]
    description: Option<String>,
    /// Optional complete desired disabled state.
    disabled: Option<bool>,
    /// Must be true to acknowledge the exact metadata or availability change.
    confirm: bool,
}

impl KmsKeyUpdateInput {
    fn into_parts(self) -> Result<(ProjectId, KmsKeyId, KmsKeyChange, bool), McpError> {
        let (project_id, key_id) = self.target.into_parts()?;
        let change = KmsKeyChange::new(
            self.name
                .map(KmsKeyName::new)
                .transpose()
                .map_err(invalid_input)?,
            self.description,
            self.disabled,
        )
        .map_err(invalid_input)?;
        Ok((project_id, key_id, change, self.confirm))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsKeyDeleteInput {
    /// Exact project and key identifiers to delete.
    target: KmsKeyTargetInput,
    /// Must be true to acknowledge permanent key deletion.
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsEncryptInput {
    /// Exact project and symmetric key identifiers used for encryption.
    target: KmsKeyTargetInput,
    /// Canonical padded base64 plaintext. This field is sensitive.
    #[serde(deserialize_with = "deserialize_secret_input")]
    #[schemars(with = "String", length(max = 699_052))]
    data: SecretValue,
    /// Must be true to acknowledge the non-replayed encryption operation.
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsDecryptInput {
    /// Exact project and symmetric key identifiers used for decryption.
    target: KmsKeyTargetInput,
    /// Canonical padded base64 ciphertext. This field is sensitive.
    #[serde(deserialize_with = "deserialize_secret_input")]
    #[schemars(with = "String", length(max = 700_416))]
    ciphertext: SecretValue,
    /// Must be true to reveal plaintext at the MCP output boundary.
    confirm_reveal: bool,
    /// Optional delivery mode for the revealed plaintext: reference stages an
    /// out-of-context envelope; inlineValue places it in the tool result. Defaults to
    /// reference when this server's transfer plane is enabled and inlineValue otherwise.
    #[serde(default)]
    delivery: Option<SecretDeliveryMode>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsPrivateKeyRevealInput {
    /// Exact project and key identifiers whose private material is revealed.
    target: KmsKeyTargetInput,
    /// Must be true to reveal private key material at the MCP output boundary.
    confirm_reveal: bool,
    /// Optional delivery mode for the revealed key: reference stages an out-of-context
    /// envelope; inlineValue places it in the tool result. Defaults to reference when
    /// this server's transfer plane is enabled and inlineValue otherwise.
    #[serde(default)]
    delivery: Option<SecretDeliveryMode>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsBulkImportEntryInput {
    /// Canonical lowercase name for the imported key.
    #[schemars(regex(pattern = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"), length(max = 32))]
    name: String,
    /// Fixed cryptographic purpose for the imported key.
    key_usage: KmsKeyUsage,
    /// Exact algorithm compatible with the selected key usage and material.
    algorithm: KmsKeyAlgorithm,
    /// Canonical padded base64 key material. This field is sensitive.
    #[serde(deserialize_with = "deserialize_secret_input")]
    #[schemars(with = "String", length(max = 87_384))]
    key_material: SecretValue,
}

impl KmsBulkImportEntryInput {
    fn into_entry(self) -> Result<KmsBulkImportEntry, McpError> {
        let key_material =
            KmsKeyMaterial::new(self.key_material, self.algorithm).map_err(invalid_input)?;
        KmsBulkImportEntry::new(
            KmsKeyName::new(self.name).map_err(invalid_input)?,
            self.key_usage,
            self.algorithm,
            key_material,
        )
        .map_err(invalid_input)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsBulkImportInput {
    /// Opaque Infisical project identifier that will own every imported key.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// One to one hundred uniquely named, typed private-key records. Aggregate decoded key material must not exceed 512 KiB.
    #[schemars(length(min = 1, max = 100))]
    keys: Vec<KmsBulkImportEntryInput>,
    /// Must be true to acknowledge persistent import of private key material.
    confirm: bool,
}

impl KmsBulkImportInput {
    pub(super) fn into_parts(self) -> Result<(ProjectId, Vec<KmsBulkImportEntry>, bool), McpError> {
        if self.keys.is_empty() || self.keys.len() > MAX_KMS_BULK_KEYS {
            return Err(McpError::invalid_params(
                "keys must contain between 1 and 100 entries",
                None,
            ));
        }
        Ok((
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            self.keys
                .into_iter()
                .map(KmsBulkImportEntryInput::into_entry)
                .collect::<Result<Vec<_>, _>>()?,
            self.confirm,
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsBulkPrivateKeyRevealInput {
    /// Opaque Infisical project identifier that must own every key.
    #[schemars(regex(pattern = r"^[A-Za-z0-9_-]{1,128}$"))]
    project_id: String,
    /// One to one hundred unique canonical KMS key UUIDs. Independent preflight reads
    /// run with bounded concurrency and a total deadline before the bulk request.
    /// Failed preflights may create access events but never send the bulk request.
    #[schemars(length(min = 1, max = 100))]
    key_ids: Vec<String>,
    /// Must be true to reveal every private key at the MCP output boundary.
    confirm_reveal: bool,
    /// Optional delivery mode for the revealed keys: reference stages one out-of-context
    /// envelope for the whole set; inlineValue places them in the tool result. Defaults
    /// to reference when this server's transfer plane is enabled and inlineValue
    /// otherwise.
    #[serde(default)]
    delivery: Option<SecretDeliveryMode>,
}

impl KmsBulkPrivateKeyRevealInput {
    pub(super) fn into_parts(self) -> Result<(ProjectId, Vec<KmsKeyId>, bool), McpError> {
        if self.key_ids.is_empty() || self.key_ids.len() > MAX_KMS_BULK_KEYS {
            return Err(McpError::invalid_params(
                "keyIds must contain between 1 and 100 entries",
                None,
            ));
        }
        Ok((
            ProjectId::new(self.project_id).map_err(invalid_input)?,
            self.key_ids
                .into_iter()
                .map(KmsKeyId::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid_input)?,
            self.confirm_reveal,
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsSignInput {
    /// Exact project and asymmetric key identifiers used for signing.
    target: KmsKeyTargetInput,
    /// Canonical padded base64 message or digest. This field is sensitive.
    #[serde(deserialize_with = "deserialize_secret_input")]
    #[schemars(with = "String", length(max = 699_052))]
    data: SecretValue,
    /// Exact signing algorithm supported by the selected key.
    signing_algorithm: KmsSigningAlgorithm,
    /// True only for an exact SHA-256/384/512 digest with RSA PKCS#1 v1.5 or ECDSA; RSA-PSS and ML-DSA require false.
    #[serde(default)]
    is_digest: bool,
    /// Must be true to acknowledge the non-replayed signing operation.
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KmsVerifyInput {
    /// Exact project and asymmetric key identifiers used for verification.
    target: KmsKeyTargetInput,
    /// Canonical padded base64 message or digest. This field is sensitive.
    #[serde(deserialize_with = "deserialize_secret_input")]
    #[schemars(with = "String", length(max = 699_052))]
    data: SecretValue,
    /// Canonical padded base64 signature to verify.
    #[schemars(length(min = 4, max = 10_924))]
    signature: String,
    /// Exact signing algorithm used to produce the signature.
    signing_algorithm: KmsSigningAlgorithm,
    /// True only for an exact SHA-256/384/512 digest with RSA PKCS#1 v1.5 or ECDSA; RSA-PSS and ML-DSA require false.
    #[serde(default)]
    is_digest: bool,
    /// Must be true to acknowledge the non-replayed verification operation.
    confirm: bool,
}

#[derive(Debug, JsonSchema)]
#[schemars(rename_all = "camelCase")]
pub(super) struct KmsDecryptedDataOutput {
    /// Canonical UUID of the key used for decryption.
    key_id: String,
    /// Explicitly revealed canonical base64 plaintext, present only for inline delivery.
    /// This field is sensitive.
    #[schemars(with = "Option<String>")]
    plaintext: Option<SecretValue>,
    /// Out-of-context reference to the plaintext, present only for reference delivery.
    /// The envelope's data carries a plaintext field.
    secret_file: Option<SecretFileReference>,
}

impl KmsDecryptedDataOutput {
    fn deliver(
        value: KmsDecryptedData,
        disposition: SecretDisposition<'_>,
    ) -> Result<Self, McpError> {
        let secret_file = disposition.stage(
            KMS_DECRYPT_TOOL,
            || serde_json::json!({ "plaintext": value.plaintext.expose_secret() }),
        )?;
        Ok(Self {
            key_id: value.key_id,
            plaintext: secret_file.is_none().then_some(value.plaintext),
            secret_file,
        })
    }
}

impl Serialize for KmsDecryptedDataOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("KmsDecryptedDataOutput", 2)?;
        output.serialize_field("keyId", &self.key_id)?;
        if let Some(value) = &self.plaintext {
            output.serialize_field("plaintext", value.expose_secret())?;
        }
        if let Some(file) = &self.secret_file {
            output.serialize_field("secretFile", file)?;
        }
        output.end()
    }
}

#[derive(Debug, JsonSchema)]
#[schemars(rename_all = "camelCase")]
pub(super) struct KmsPrivateKeyOutput {
    /// Canonical UUID of the revealed key.
    key_id: String,
    /// Explicitly revealed canonical base64 private key, present only for inline
    /// delivery. This field is sensitive.
    #[schemars(with = "Option<String>")]
    private_key: Option<SecretValue>,
    /// Out-of-context reference to the private key, present only for reference delivery.
    /// The envelope's data carries a privateKey field.
    secret_file: Option<SecretFileReference>,
}

impl KmsPrivateKeyOutput {
    fn deliver(value: KmsPrivateKey, disposition: SecretDisposition<'_>) -> Result<Self, McpError> {
        let secret_file = disposition.stage(
            KMS_PRIVATE_KEY_REVEAL_TOOL,
            || serde_json::json!({ "privateKey": value.private_key.expose_secret() }),
        )?;
        Ok(Self {
            key_id: value.key_id,
            private_key: secret_file.is_none().then_some(value.private_key),
            secret_file,
        })
    }
}

impl Serialize for KmsPrivateKeyOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("KmsPrivateKeyOutput", 2)?;
        output.serialize_field("keyId", &self.key_id)?;
        if let Some(value) = &self.private_key {
            output.serialize_field("privateKey", value.expose_secret())?;
        }
        if let Some(file) = &self.secret_file {
            output.serialize_field("secretFile", file)?;
        }
        output.end()
    }
}

#[derive(Debug, JsonSchema)]
#[schemars(rename_all = "camelCase")]
pub(super) struct KmsBulkPrivateKeyOutput {
    /// Canonical UUID of the revealed key.
    key_id: String,
    /// Canonical key name reflected by the exact preflight.
    name: String,
    /// Fixed cryptographic purpose of the key.
    key_usage: KmsKeyUsage,
    /// Exact algorithm of the key.
    algorithm: KmsKeyAlgorithm,
    /// Explicitly revealed canonical base64 private key, present only for inline
    /// delivery. This field is sensitive.
    #[schemars(with = "Option<String>")]
    private_key: Option<SecretValue>,
    /// Optional canonical base64 public key.
    public_key: Option<String>,
}

impl Serialize for KmsBulkPrivateKeyOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("KmsBulkPrivateKeyOutput", 6)?;
        output.serialize_field("keyId", &self.key_id)?;
        output.serialize_field("name", &self.name)?;
        output.serialize_field("keyUsage", &self.key_usage)?;
        output.serialize_field("algorithm", &self.algorithm)?;
        if let Some(value) = &self.private_key {
            output.serialize_field("privateKey", value.expose_secret())?;
        }
        output.serialize_field("publicKey", &self.public_key)?;
        output.end()
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KmsBulkPrivateKeysOutput {
    /// Opaque project identifier validated for every returned key.
    project_id: String,
    /// Exact bounded set of revealed keys; their private material is inline only for
    /// inline delivery.
    keys: Vec<KmsBulkPrivateKeyOutput>,
    /// Out-of-context reference to every revealed private key, present only for
    /// reference delivery. The envelope's data carries a keys array of keyId, name, and
    /// privateKey fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_file: Option<SecretFileReference>,
}

impl KmsBulkPrivateKeysOutput {
    fn deliver(
        project_id: String,
        keys: Vec<KmsBulkPrivateKey>,
        disposition: SecretDisposition<'_>,
    ) -> Result<Self, McpError> {
        let secret_file = disposition.stage(KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL, || {
            serde_json::json!({
                "keys": keys
                    .iter()
                    .map(|key| {
                        serde_json::json!({
                            "keyId": key.key_id,
                            "name": key.name,
                            "privateKey": key.private_key.expose_secret(),
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        })?;
        let inline = secret_file.is_none();
        Ok(Self {
            project_id,
            keys: keys
                .into_iter()
                .map(|key| KmsBulkPrivateKeyOutput {
                    key_id: key.key_id,
                    name: key.name,
                    key_usage: key.key_usage,
                    algorithm: key.algorithm,
                    private_key: inline.then_some(key.private_key),
                    public_key: key.public_key,
                })
                .collect(),
            secret_file,
        })
    }
}

pub(super) async fn dispatch_kms_workflow(
    client: &InfisicalClient,
    files: Option<&SecretFilePlane>,
    params: &mut CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    if matches!(
        params.name.as_ref(),
        KMS_KEYS_LIST_TOOL
            | KMS_KEYS_GET_TOOL
            | KMS_KEYS_GET_BY_NAME_TOOL
            | KMS_KEYS_CREATE_TOOL
            | KMS_KEYS_UPDATE_TOOL
            | KMS_KEYS_DELETE_TOOL
    ) {
        return dispatch_kms_management_workflow(client, params).await;
    }
    if matches!(
        params.name.as_ref(),
        KMS_PUBLIC_KEY_GET_TOOL
            | KMS_PRIVATE_KEY_REVEAL_TOOL
            | KMS_KEYS_BULK_IMPORT_TOOL
            | KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL
            | KMS_SIGNING_ALGORITHMS_LIST_TOOL
    ) {
        return dispatch_kms_material_workflow(client, files, params).await;
    }
    dispatch_kms_cryptographic_workflow(client, files, params).await
}

async fn dispatch_kms_management_workflow(
    client: &InfisicalClient,
    params: &mut CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    match params.name.as_ref() {
        KMS_KEYS_LIST_TOOL => {
            let input = parse_arguments::<KmsKeysListInput>(
                params,
                "kms.keys.list arguments do not match the declared schema",
            )?;
            tool_result(client.list_kms_keys(input.into_request()?).await)
        }
        KMS_KEYS_GET_TOOL => {
            let input = parse_arguments::<KmsKeyTargetInput>(
                params,
                "kms.keys.get arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.into_parts()?;
            tool_result(client.get_kms_key(&project_id, &key_id).await)
        }
        KMS_KEYS_GET_BY_NAME_TOOL => {
            let input = parse_arguments::<KmsKeyByNameInput>(
                params,
                "kms.keys.getByName arguments do not match the declared schema",
            )?;
            let (project_id, key_name) = input.into_parts()?;
            tool_result(client.get_kms_key_by_name(&project_id, &key_name).await)
        }
        KMS_KEYS_CREATE_TOOL => {
            let input = parse_arguments::<KmsKeyCreateInput>(
                params,
                "kms.keys.create arguments do not match the declared schema",
            )?;
            let (project_id, creation, confirm) = input.into_parts()?;
            tool_result(client.create_kms_key(&project_id, creation, confirm).await)
        }
        KMS_KEYS_UPDATE_TOOL => {
            let input = parse_arguments::<KmsKeyUpdateInput>(
                params,
                "kms.keys.update arguments do not match the declared schema",
            )?;
            let (project_id, key_id, change, confirm) = input.into_parts()?;
            tool_result(
                client
                    .update_kms_key(&project_id, &key_id, change, confirm)
                    .await,
            )
        }
        KMS_KEYS_DELETE_TOOL => {
            let input = parse_arguments::<KmsKeyDeleteInput>(
                params,
                "kms.keys.delete arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.target.into_parts()?;
            tool_result(
                client
                    .delete_kms_key(&project_id, &key_id, input.confirm)
                    .await,
            )
        }
        _ => Err(McpError::method_not_found::<
            rmcp::model::CallToolRequestMethod,
        >()),
    }
}

async fn dispatch_kms_material_workflow(
    client: &InfisicalClient,
    files: Option<&SecretFilePlane>,
    params: &mut CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    match params.name.as_ref() {
        KMS_PUBLIC_KEY_GET_TOOL => {
            let input = parse_arguments::<KmsKeyTargetInput>(
                params,
                "kms.keys.publicKey.get arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.into_parts()?;
            tool_result(client.get_kms_public_key(&project_id, &key_id).await)
        }
        KMS_PRIVATE_KEY_REVEAL_TOOL => {
            let input = parse_arguments::<KmsPrivateKeyRevealInput>(
                params,
                "kms.keys.privateKey.reveal arguments do not match the declared schema",
            )?;
            let disposition = resolve_delivery(files, input.delivery)?;
            let (project_id, key_id) = input.target.into_parts()?;
            delivered_result(
                client
                    .reveal_kms_private_key(&project_id, &key_id, input.confirm_reveal)
                    .await,
                |key| KmsPrivateKeyOutput::deliver(key, disposition),
            )
        }
        KMS_KEYS_BULK_IMPORT_TOOL => {
            let input = parse_arguments::<KmsBulkImportInput>(
                params,
                "kms.keys.bulkImport arguments do not match the declared schema",
            )?;
            let (project_id, keys, confirm) = input.into_parts()?;
            tool_result(
                client
                    .bulk_import_kms_keys(&project_id, keys, confirm)
                    .await,
            )
        }
        KMS_PRIVATE_KEYS_BULK_REVEAL_TOOL => {
            let input = parse_arguments::<KmsBulkPrivateKeyRevealInput>(
                params,
                "kms.keys.privateKeys.bulkReveal arguments do not match the declared schema",
            )?;
            let disposition = resolve_delivery(files, input.delivery)?;
            let (project_id, key_ids, confirm_reveal) = input.into_parts()?;
            let project_id_output = project_id.as_str().to_owned();
            delivered_result(
                client
                    .bulk_reveal_kms_private_keys(&project_id, key_ids, confirm_reveal)
                    .await,
                |keys| KmsBulkPrivateKeysOutput::deliver(project_id_output, keys, disposition),
            )
        }
        KMS_SIGNING_ALGORITHMS_LIST_TOOL => {
            let input = parse_arguments::<KmsKeyTargetInput>(
                params,
                "kms.keys.signingAlgorithms.list arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.into_parts()?;
            tool_result(
                client
                    .list_kms_signing_algorithms(&project_id, &key_id)
                    .await,
            )
        }
        _ => Err(McpError::method_not_found::<
            rmcp::model::CallToolRequestMethod,
        >()),
    }
}

async fn dispatch_kms_cryptographic_workflow(
    client: &InfisicalClient,
    files: Option<&SecretFilePlane>,
    params: &mut CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    match params.name.as_ref() {
        KMS_ENCRYPT_TOOL => {
            let input = parse_arguments::<KmsEncryptInput>(
                params,
                "kms.encrypt arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.target.into_parts()?;
            let data = KmsData::new(input.data).map_err(invalid_input)?;
            tool_result(
                client
                    .kms_encrypt(&project_id, &key_id, data, input.confirm)
                    .await,
            )
        }
        KMS_DECRYPT_TOOL => {
            let input = parse_arguments::<KmsDecryptInput>(
                params,
                "kms.decrypt arguments do not match the declared schema",
            )?;
            let disposition = resolve_delivery(files, input.delivery)?;
            let (project_id, key_id) = input.target.into_parts()?;
            delivered_result(
                client
                    .kms_decrypt(&project_id, &key_id, input.ciphertext, input.confirm_reveal)
                    .await,
                |data| KmsDecryptedDataOutput::deliver(data, disposition),
            )
        }
        KMS_SIGN_TOOL => {
            let input = parse_arguments::<KmsSignInput>(
                params,
                "kms.sign arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.target.into_parts()?;
            let data = KmsData::new(input.data).map_err(invalid_input)?;
            tool_result(
                client
                    .kms_sign(
                        &project_id,
                        &key_id,
                        data,
                        input.signing_algorithm,
                        input.is_digest,
                        input.confirm,
                    )
                    .await,
            )
        }
        KMS_VERIFY_TOOL => {
            let input = parse_arguments::<KmsVerifyInput>(
                params,
                "kms.verify arguments do not match the declared schema",
            )?;
            let (project_id, key_id) = input.target.into_parts()?;
            let data = KmsData::new(input.data).map_err(invalid_input)?;
            tool_result(
                client
                    .kms_verify(
                        &project_id,
                        &key_id,
                        data,
                        input.signature,
                        input.signing_algorithm,
                        input.is_digest,
                        input.confirm,
                    )
                    .await,
            )
        }
        _ => Err(McpError::method_not_found::<
            rmcp::model::CallToolRequestMethod,
        >()),
    }
}
