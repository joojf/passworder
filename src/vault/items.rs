use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VaultItemType {
    Login,
    SecureNote,
    ApiToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultItemV1 {
    #[serde(with = "uuid_as_string")]
    pub id: Uuid,
    #[serde(rename = "type")]
    pub item_type: VaultItemType,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(serialize_with = "serialize_secret")]
    pub secret: SecretString,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultPayloadV1 {
    pub schema_version: u32,
    #[serde(default)]
    pub items: Vec<VaultItemV1>,
}

impl Default for VaultPayloadV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            items: Vec::new(),
        }
    }
}

fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

pub mod uuid_as_string {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use uuid::Uuid;

    pub fn serialize<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&uuid.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uuid::parse_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_secret() {
        let item: VaultItemV1 = serde_json::from_str(
            r#"{
                "id": "00000000-0000-0000-0000-000000000000",
                "type": "login",
                "name": "github",
                "secret": "s3cr3t",
                "created_at": 0,
                "updated_at": 0
            }"#,
        )
        .expect("valid item");

        assert!(!format!("{item:?}").contains("s3cr3t"));
        assert_eq!(item.secret.expose_secret(), "s3cr3t");
    }
}
