use dotenv;
use hmacsha1::hmac_sha1;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use lambda_http::{lambda, Body, IntoResponse, Request, RequestExt, Response};
use lambda_runtime::error::HandlerError;
use lambda_runtime::Context;
use lazy_static::lazy_static;
use log::{debug, error, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt::Write;

mod fastspring;

lazy_static! {
    static ref KEYGEN_ADMIN_TOKEN: String = env::var("KEYGEN_ADMIN_TOKEN").unwrap();
    static ref KEYGEN_ACCOUNT_ID: String = env::var("KEYGEN_ACCOUNT_ID").unwrap();
    static ref KEYGEN_POLICY_ID: String = env::var("KEYGEN_POLICY_ID").unwrap();
}

fn router(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    debug!("router request={:?}", req);
    debug!("path={:?}", req.uri().path());
    debug!("query={:?}", req.query_string_parameters());

    let client = reqwest::Client::new();

    match req.uri().path() {
        "/test/keygen/create" => match *req.method() {
            http::Method::POST => handle_keygen_create( req, c),
            _ => not_allowed(req, c),
        },
        /*"/test/subscription_cancelled" => match *req.method() {
            http::Method::POST => handle_subscription_cancelled(req, c),
            _ => not_allowed(req, c),
        },*/
        "/test/subscriptionDeactivated" => match *req.method() {
            http::Method::POST => handle_fastspring_webhook(&client, req, c),
            _ => not_allowed(req, c),
        },
        _ => not_found(req, c),
    }
}

fn body_to_json(body: &Body) -> Result<Value, HandlerError> {
    Ok(serde_json::from_str(match body {
        Body::Text(ref s) => s,
        _ => return Err("invalid json".into()),
    })
    .map_err(|_| "invalid json")?)
}

/*
fn licenses_from_order(order_json: &Value) -> Result<Vec<&str>, HandlerError> {
    Ok(order_json["order"]["licenses"]
        .as_array()
        .ok_or("invalid request")?
        .iter()
        .map(|lic| lic["key"].as_str().ok_or("invalid request"))
        .collect::<Result<Vec<_>, _>>()?)
}*/


fn license_key(code: &str) -> Option<&str> {
    code.split('.').nth(1)
}

fn handle_fastspring_webhook(client: &reqwest::Client, req: Request, c: Context)-> Result<Response<Body>, HandlerError> {
    if !fastspring::authentify_web_hook(&req) {
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let events_json = body_to_json(req.body())?;
    let events_json = events_json["events"].as_array().ok_or("invalid format")?;

    for e in events_json {
        let ty = e["type"].as_str().ok_or("invalid format")?;
        let data = &e["data"];
        match ty {
            "subscription.deactivated" => handle_subscription_deactivated(client, data)?,
            _ => unimplemented!()
        };
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(Body::default())
        .unwrap())
}

/// Handles deactivation of subscriptions.
///
/// This will suspend all licenses associated with the order.
fn handle_subscription_deactivated(client: &reqwest::Client, data: &serde_json::Value) -> Result<Response<Body>, HandlerError> {
    debug!("handle_subscription_deactivated {:?}", data);

    let subscription_id = data["id"].as_str().ok_or("invalid format")?;
    debug!("Subscription deactivated: {}", subscription_id);

    let order = fastspring::get_subscription_entries(client, subscription_id)?;
    let order_items = order[0]["order"]["items"].as_array().ok_or("invalid format")?;

    // Collect all licenses to revoke
    let mut licenses_to_revoke = Vec::new();
    for item in order_items.iter() {
        let product = &item["product"];
        for (k,v) in item["fulfillments"].as_object().ok_or("invalid format")?.iter() {
            if let Some(licenses) = v.as_array() {
                for l in licenses {
                    let code = l["license"].as_str().ok_or("invalid format")?;
                    licenses_to_revoke.push(String::from(code));
                }
            }
        }
    }

    // revoke all licenses
    for lic in licenses_to_revoke.iter() {
        let key = license_key(lic).ok_or("invalid license key")?;
        suspend_license(key)?;
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(().into())
        .unwrap())
}

/// Suspends a license by license key.
fn suspend_license(license_key: &str) -> Result<(), HandlerError> {
    modify_license(license_key, LicenseAction::Suspend)
}

/// Reinstates (un-suspends) a license by license key.
fn reinstate_license(license_key: &str) -> Result<(), HandlerError> {
    modify_license(license_key, LicenseAction::Reinstate)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LicenseAction {
    Suspend,
    Reinstate,
}

fn modify_license(license_key: &str, action: LicenseAction) -> Result<(), HandlerError> {
    let action_verb = match action {
        LicenseAction::Suspend => "suspend",
        LicenseAction::Reinstate => "reinstate",
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

fn generate_licenses(subscription: &str, policy: &str, quantity: u32) -> Result<Vec<String>,HandlerError>
{
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


/// Handles license creation requests (coming from FastSpring).
/// A new license will be created for the product_id and policy_id passed in the URL parameters.
/// The generated license has no expiration date: they are explicitly revoked via a SendOwl web hook
/// (see [handle_subscription_cancelled]) when the subscription is cancelled.
///
fn handle_keygen_create(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    // first, authentify request from sendowl
    if !fastspring::verify_signed_url(&req) {
        // Wrong signature
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    // get product ID and policy ID and order ID
    let params : HashMap<_,_> = url::form_urlencoded::parse(match req.body() {
        Body::Text(ref s) => s.as_bytes(),
        _ => return Err("invalid request body".into())
    }).collect();

    debug!("params = {:?}", params);

    let subscription = params.get("subscription").ok_or("invalid query parameters")?;
    let policy_id = params.get("policy").ok_or("invalid query parameters")?;
    let quantity : u32 = params.get("quantity").ok_or("invalid query parameters")?.parse()?;

    let codes = generate_licenses(subscription, policy_id, quantity)?.join("\n");

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(codes.into())
        .unwrap())
}

fn not_found(_req: Request, _c: Context) -> Result<Response<Body>, HandlerError> {
    Ok(Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .body(Body::default())
        .unwrap())
}

fn not_allowed(_req: Request, _c: Context) -> Result<Response<Body>, HandlerError> {
    Ok(Response::builder()
        .status(http::StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::default())
        .unwrap())
}

fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    simple_logger::init_with_level(log::Level::Debug).unwrap();
    lambda!(router);
    Ok(())
}
