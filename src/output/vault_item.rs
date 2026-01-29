use crate::vault;
use serde_json::json;

pub fn vault_item_summary_text(item: &vault::VaultItemV1) -> String {
    let path = item.path.as_deref().unwrap_or("");
    format!(
        "{}\t{}\t{}\t{}",
        item.id,
        vault_item_type_str(item.item_type),
        path,
        item.name
    )
}

pub fn vault_item_summary_json(item: &vault::VaultItemV1) -> serde_json::Value {
    json!({
        "id": item.id.to_string(),
        "type": vault_item_type_str(item.item_type),
        "name": item.name.as_str(),
        "path": item.path.as_deref(),
        "tags": &item.tags,
        "username": item.username.as_deref(),
        "urls": &item.urls,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    })
}

pub fn vault_item_json(item: &vault::VaultItemV1, reveal: bool) -> serde_json::Value {
    if reveal {
        json!({
            "id": item.id.to_string(),
            "type": vault_item_type_str(item.item_type),
            "name": item.name.as_str(),
            "path": item.path.as_deref(),
            "tags": &item.tags,
            "username": item.username.as_deref(),
            "secret": item.secret.as_str(),
            "urls": &item.urls,
            "notes": item.notes.as_deref(),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        })
    } else {
        json!({
            "id": item.id.to_string(),
            "type": vault_item_type_str(item.item_type),
            "name": item.name.as_str(),
            "path": item.path.as_deref(),
            "tags": &item.tags,
            "username": item.username.as_deref(),
            "secret_redacted": true,
            "urls": &item.urls,
            "notes": item.notes.as_deref(),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        })
    }
}

pub fn vault_item_text(item: &vault::VaultItemV1, reveal: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("id:\t{}\n", item.id));
    out.push_str(&format!("type:\t{}\n", vault_item_type_str(item.item_type)));
    out.push_str(&format!("name:\t{}\n", item.name));
    if let Some(path) = &item.path {
        out.push_str(&format!("path:\t{}\n", path));
    }
    if !item.tags.is_empty() {
        out.push_str(&format!("tags:\t{}\n", item.tags.join(",")));
    }
    if let Some(username) = &item.username {
        out.push_str(&format!("username:\t{}\n", username));
    }
    if !item.urls.is_empty() {
        out.push_str(&format!("urls:\t{}\n", item.urls.join(",")));
    }
    if let Some(notes) = &item.notes {
        out.push_str(&format!("notes:\t{}\n", notes));
    }
    out.push_str(&format!(
        "secret:\t{}\n",
        if reveal { &item.secret } else { "[REDACTED]" }
    ));
    out.push_str(&format!("created_at:\t{}\n", item.created_at));
    out.push_str(&format!("updated_at:\t{}", item.updated_at));
    out
}

pub fn vault_item_type_str(t: vault::VaultItemType) -> &'static str {
    match t {
        vault::VaultItemType::Login => "login",
        vault::VaultItemType::SecureNote => "secure-note",
        vault::VaultItemType::ApiToken => "api-token",
    }
}
