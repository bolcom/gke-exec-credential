use chrono::{DateTime, Utc, Duration};
use std::process::Command;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{PathBuf};
use std::fs::OpenOptions;
use anyhow::Result;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    api_version: String,
    kind: String,
    status: ExecCredentialStatus
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialStatus {
    token: String,
    expiration_timestamp: String
}

fn get_token_filename() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.parent().expect("Could not determine executable path").join("gke-exec-credential-cached"))
}

fn get_cached_token() -> Result<Option<ExecCredential>> {
    if get_token_filename()?.exists() {
        let data = fs::read_to_string(get_token_filename()?)?;
        Ok(Some(serde_json::from_str::<ExecCredential>(&data)?))
    } else {
        Ok(None)
    }
}

fn is_token_valid(token: &ExecCredential) -> Result<bool> {
    let expiry = DateTime::parse_from_rfc3339(&token.status.expiration_timestamp)?;

    // When the token is valid for less than 30 seconds we still consider it expired
    let expiry = expiry - Duration::seconds(30);
    Ok(Utc::now().lt(&expiry))
}

fn refresh_token() -> Result<ExecCredential> {
    let output = Command::new("gcloud")
        .arg("config")
        .arg("config-helper")
        .arg("--format=json")
        .arg("--force-auth-refresh")
        .output()?;
    let err = &String::from_utf8(output.stderr)?;
    if !err.is_empty() {
        return Err(anyhow::anyhow!("gke-exec-credential encountered a problem invoking 'gcloud'.\n\n{}", err));
    }
    let json = &String::from_utf8(output.stdout)?;
    let result: HashMap<String, Value> = serde_json::from_str(json)?;
    let token = result["credential"]["access_token"].as_str().unwrap().into();
    let expiration_timestamp = result["credential"]["token_expiry"].as_str().unwrap().into();

    let new_token = ExecCredential {
        api_version: "client.authentication.k8s.io/v1beta1".into(),
        kind: "ExecCredential".into(),
        status: ExecCredentialStatus {
            token,
            expiration_timestamp
        }
    };
    let file = OpenOptions::new().write(true).truncate(true).create(true).open(get_token_filename()?)?;
    serde_json::to_writer(&file, &new_token)?;

    Ok(new_token)
}

fn main() -> Result<()> {
    let cached_token = get_cached_token()?;
    let cached_token = match cached_token {
        Some(tok) => {
            if is_token_valid(&tok)? {
                tok
            } else {
                refresh_token()?
            }
        },
        None => refresh_token()?
    };

    println!("{}", serde_json::to_string_pretty(&cached_token)?);
    Ok(())
}
