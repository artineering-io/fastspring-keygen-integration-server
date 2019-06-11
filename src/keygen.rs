use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use lambda_runtime::error::HandlerError;
use lazy_static::lazy_static;
use log::{debug};
use rand::Rng;
use serde_json::json;
use std::env;

lazy_static! {
    static ref KEYGEN_ADMIN_TOKEN: String = env::var("KEYGEN_ADMIN_TOKEN").unwrap();
    static ref KEYGEN_ACCOUNT_ID: String = env::var("KEYGEN_ACCOUNT_ID").unwrap();
    //static ref KEYGEN_POLICY_ID: String = env::var("KEYGEN_POLICY_ID").unwrap();
}

/// Suspends a license by license key.
pub fn suspend_license(license_key: &str) -> Result<(), HandlerError> {
    modify_license(license_key, LicenseAction::Suspend)
}

/*
/// Reinstates (un-suspends) a license by license key.
pub fn reinstate_license(license_key: &str) -> Result<(), HandlerError> {
    modify_license(license_key, LicenseAction::Reinstate)
}*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LicenseAction {
    Suspend,
    //Reinstate,
}

fn modify_license(license_key: &str, action: LicenseAction) -> Result<(), HandlerError> {
    let action_verb = match action {
        LicenseAction::Suspend => "suspend",
        //LicenseAction::Reinstate => "reinstate",
    };

    let client = reqwest::Client::new();
    let reply = client
        .post(&format!(
            "https://api.keygen.sh/v1/accounts/{}/licenses/{}/actions/{}",
            *KEYGEN_ACCOUNT_ID, license_key, action_verb
        ))
        .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_ADMIN_TOKEN))
        .header(ACCEPT, "application/vnd.api+json")
        .send()
        .map_err(|_| "request error")?;

    debug!(
        "{} license {} status {}",
        action_verb,
        license_key,
        reply.status()
    );
    Ok(())
}

pub fn generate_licenses(
    subscription: &str,
    policy: &str,
    quantity: u32,
) -> Result<Vec<String>, HandlerError> {
    // create license
    // 16-byte random number, hex encoded
    let client = reqwest::Client::new();
    let mut codes = Vec::new();

    debug!("Generating {} licenses with policy {}", quantity, policy);

    for _ in 0..quantity {
        let mut lic = [0u8; 16];
        let mut rng = rand::thread_rng();
        rng.fill(&mut lic);
        let lic = hex::encode(lic);

        let req_body = json!({
            "data": {
                "type": "licenses",
                "attributes": {
                    "key": lic,
                    "metadata": {
                        "fastSpringSubscriptionId": subscription
                    }
                },
                "relationships": {
                    "policy": {
                        "data": { "type": "policies", "id": policy }
                    }
                }
            }
        });

        let reply: serde_json::Value = client
            .post(&format!(
                "https://api.keygen.sh/v1/accounts/{}/licenses",
                *KEYGEN_ACCOUNT_ID
            ))
            .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_ADMIN_TOKEN))
            .header(CONTENT_TYPE, "application/vnd.api+json")
            .header(ACCEPT, "application/vnd.api+json")
            .body(req_body.to_string())
            .send()
            .map_err(|_| "request error")?
            .json()
            .map_err(|_| "invalid json")?;

        let license_id = reply["data"]["id"].as_str().ok_or("invalid reply")?;
        let license_key = reply["data"]["attributes"]["key"]
            .as_str()
            .ok_or("invalid reply")?;

        //-------------------------------------------
        // generate activation token for license
        let req_body = json!({
            "data": {
                "type": "tokens",
                "attributes": {}
            }
        });
        let reply: serde_json::Value = client
            .post(&format!(
                "https://api.keygen.sh/v1/accounts/{}/licenses/{}/tokens",
                *KEYGEN_ACCOUNT_ID, license_id
            ))
            .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_ADMIN_TOKEN))
            .header(CONTENT_TYPE, "application/vnd.api+json")
            .header(ACCEPT, "application/vnd.api+json")
            .body(req_body.to_string())
            .send()
            .map_err(|_| "request error")?
            .json()
            .map_err(|_| "invalid json")?;

        let activation_token = reply["data"]["attributes"]["token"]
            .as_str()
            .ok_or("invalid reply")?;

        // return activation code (activation token + license key)
        let code = format!("{}.{}", activation_token, license_key);
        codes.push(code)
    }
    Ok(codes)
}
