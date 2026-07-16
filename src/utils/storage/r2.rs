use std::env;
use std::sync::OnceLock;

use aws_credential_types::Credentials;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

use crate::utils::file_hash::sha256_hex;

#[derive(Debug)]
pub enum StorageError {
    NotConfigured(String),
    InitFailed(String),
    OperationFailed(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured(msg) => write!(f, "Storage not configured: {msg}"),
            Self::InitFailed(msg) => write!(f, "Storage init failed: {msg}"),
            Self::OperationFailed(msg) => write!(f, "Storage operation failed: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

pub struct R2Storage {
    client: Client,
    public_bucket: String,
}

static STORAGE: OnceLock<R2Storage> = OnceLock::new();

fn required_env(name: &str) -> Result<String, StorageError> {
    env::var(name).map_err(|_| {
        StorageError::NotConfigured(format!("missing environment variable {name}"))
    })
}

fn build_client() -> Result<Client, StorageError> {
    let account_id = required_env("R2_ACCOUNT_ID")?;
    let access_key = required_env("R2_ACCESS_KEY_ID")?;
    let secret_key = required_env("R2_SECRET_ACCESS_KEY")?;

    let credentials = Credentials::new(access_key, secret_key, None, None, "r2");
    let endpoint = format!("https://{account_id}.r2.cloudflarestorage.com");

    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(aws_sdk_s3::config::Region::new("auto"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();

    Ok(Client::from_conf(config))
}

impl R2Storage {
    fn from_env() -> Result<Self, StorageError> {
        let client = build_client()?;
        let public_bucket = required_env("R2_PUBLIC_BUCKET")?;

        Ok(Self {
            client,
            public_bucket,
        })
    }

    pub async fn put_public(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.public_bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type(content_type)
            .cache_control("public, max-age=31536000, immutable")
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("put_public {key}: {e}")))?;
        Ok(())
    }

    pub async fn delete_public(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.public_bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("delete_public {key}: {e}")))?;
        Ok(())
    }

    pub async fn head_public(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.head_public_content_length(key).await?.is_some())
    }

    pub async fn head_public_content_length(&self, key: &str) -> Result<Option<u64>, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.public_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => Ok(output.content_length().map(|len| len as u64)),
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("NotFound") || msg.contains("404") {
                    Ok(None)
                } else {
                    Err(StorageError::OperationFailed(format!(
                        "head_public {key}: {err}"
                    )))
                }
            }
        }
    }

    pub async fn delete_attachment_key(&self, key: &str) -> Result<(), StorageError> {
        if !crate::utils::storage::is_attachment_key(key) {
            return Ok(());
        }
        let result = self.delete_public(key).await;
        if let Some(thumb) = crate::utils::storage::attachment_thumb_key(key) {
            let _ = self.delete_public(&thumb).await;
        }
        result
    }

    pub async fn delete_avatar_key(&self, key: &str) -> Result<(), StorageError> {
        if crate::utils::storage::is_avatar_key(key) {
            self.delete_public(key).await
        } else {
            Ok(())
        }
    }

    pub async fn delete_public_media_key(&self, key: &str) -> Result<(), StorageError> {
        if crate::utils::storage::is_public_media_key(key) {
            self.delete_public(key).await
        } else {
            Ok(())
        }
    }

    pub async fn list_public_attachments(&self) -> Result<Vec<(String, u64)>, StorageError> {
        let mut objects = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.public_bucket)
                .prefix("attachments/");

            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }

            let output = request
                .send()
                .await
                .map_err(|e| StorageError::OperationFailed(format!("list_public: {e}")))?;

            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                if !crate::utils::storage::is_attachment_key(key) {
                    continue;
                }
                objects.push((key.to_string(), object.size().unwrap_or(0) as u64));
            }

            continuation = output.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break;
            }
        }

        Ok(objects)
    }

    /// Fetches a public object's bytes and content-type, streaming directly from
    /// R2 via the S3 API (bypasses the public CDN domain entirely).
    pub async fn get_public_object(
        &self,
        key: &str,
    ) -> Result<Option<(Vec<u8>, Option<String>)>, StorageError> {
        let output = match self
            .client
            .get_object()
            .bucket(&self.public_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("NoSuchKey") || msg.contains("NotFound") || msg.contains("404") {
                    return Ok(None);
                }
                return Err(StorageError::OperationFailed(format!(
                    "get_public {key}: {err}"
                )));
            }
        };

        let content_type = output.content_type().map(|s| s.to_string());
        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("read_public {key}: {e}")))?
            .into_bytes()
            .to_vec();

        Ok(Some((bytes, content_type)))
    }

    pub async fn verify_public_sha256(&self, key: &str, expected_hex: &str) -> Result<bool, StorageError> {
        let expected = expected_hex.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(false);
        }

        let output = self
            .client
            .get_object()
            .bucket(&self.public_bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("get_public {key}: {e}")))?;

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("read_public {key}: {e}")))?
            .into_bytes();

        Ok(sha256_hex(&bytes) == expected)
    }
}

pub fn init_storage() -> Result<(), StorageError> {
    let storage = R2Storage::from_env()?;
    let public_bucket = storage.public_bucket.clone();
    STORAGE
        .set(storage)
        .map_err(|_| StorageError::InitFailed("storage already initialized".into()))?;
    log::info!(
        "R2 storage ready (public={public_bucket}, cdn={})",
        cdn_public_base_url()
    );
    Ok(())
}

pub fn storage() -> &'static R2Storage {
    STORAGE
        .get()
        .expect("R2 storage not initialized — call init_storage() at startup")
}

pub fn cdn_public_base_url() -> String {
    env::var("CDN_PUBLIC_BASE_URL").unwrap_or_else(|_| "https://cdn.klovy.chat".to_string())
}

pub fn public_media_url(key: &str) -> String {
    let base = cdn_public_base_url().trim_end_matches('/').to_string();
    let normalized = key.trim_start_matches('/');
    format!("{base}/{normalized}")
}
