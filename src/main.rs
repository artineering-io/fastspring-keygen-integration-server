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

lazy_static! {
    static ref SENDOWL_API_KEY: String = env::var("SENDOWL_API_KEY").unwrap();
    static ref SENDOWL_SIGNING_KEY: String = env::var("SENDOWL_SIGNING_KEY").unwrap();
    static ref SENDOWL_SIGNING_KEY_SECRET: String = env::var("SENDOWL_SIGNING_KEY_SECRET").unwrap();
    static ref KEYGEN_PRODUCT_TOKEN: String = env::var("KEYGEN_PRODUCT_TOKEN").unwrap();
    static ref KEYGEN_ACCOUNT_ID: String = env::var("KEYGEN_ACCOUNT_ID").unwrap();
    static ref KEYGEN_POLICY_ID: String = env::var("KEYGEN_POLICY_ID").unwrap();
}

/// According to https://help.sendowl.com/help/signed-urls
fn sendowl_verify_signed_url(req: &Request) -> bool {
    // collect query parameters
    let mut sig = "";
    let mut p = Vec::new();
    let query_params = req.query_string_parameters();

    for (k, v) in query_params.iter() {
        if k == "signature" {
            sig = v;
        } else {
            p.push((k, v));
        }
    }
    // sort by key
    p.sort();

    // print query string
    let mut qstr = String::new();
    for i in 0..p.len() {
        //if (i != p.len()-1) {
        qstr.push_str(p[i].0);
        qstr.push_str("=");
        qstr.push_str(p[i].1);
        qstr.push_str("&");
        /*} else {
            qstr.push_str(p[i].0);
            qstr.push_str("=");
            qstr.push_str(p[i].1);
        }*/
    }
    // append secret
    write!(qstr, "secret={}", *SENDOWL_SIGNING_KEY_SECRET);
    //debug!("qstr={}", qstr);
    // make key
    let key = format!("{}&{}", *SENDOWL_SIGNING_KEY, *SENDOWL_SIGNING_KEY_SECRET);
    // sign
    let calc_sig = hmac_sha1(key.as_bytes(), qstr.as_bytes());
    // base64 encode
    let calc_sig = base64::encode(&calc_sig[..]);

    debug!("sig={}, calc_sig={}", sig, &calc_sig[..]);
    // compare
    let ok = sig == &calc_sig[..];
    if ok {
        debug!("Authenticated request from SendOwl");
    } else {
        error!("Signature check failed");
    }
    ok
}

fn sendowl_authentify_web_hook(req: &Request) -> bool {
    // TODO
    true
}

fn router(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    debug!("router request={:?}", req);
    debug!("path={:?}", req.uri().path());
    debug!("query={:?}", req.query_string_parameters());

    match req.uri().path() {
        "/test/keygen/create" => match *req.method() {
            http::Method::GET => handle_keygen_create(req, c),
            _ => not_allowed(req, c),
        },
        "/test/subscription_cancelled" => match *req.method() {
            http::Method::POST => handle_subscription_cancelled(req, c),
            _ => not_allowed(req, c),
        },
        "/test/subscription_activated" => match *req.method() {
            http::Method::POST => handle_subscription_activated(req, c),
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

fn licenses_from_order(order_json: &Value) -> Result<Vec<&str>, HandlerError> {
    Ok(order_json["order"]["licenses"]
        .as_array()
        .ok_or("invalid request")?
        .iter()
        .map(|lic| lic["key"].as_str().ok_or("invalid request"))
        .collect::<Result<Vec<_>, _>>()?)
}

fn license_key(code: &str) -> Option<&str> {
    code.split('.').nth(1)
}

/// Handles creation or reactivation of subscriptions.
///
/// Reinstates all licenses associated with the order.
fn handle_subscription_activated(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    debug!("handle_subscription_activated");
    // first, authentify request from sendowl
    if !sendowl_authentify_web_hook(&req) {
        // Wrong signature
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let order_json = body_to_json(req.body())?;
    let licenses = licenses_from_order(&order_json)?;

    // reinstate all licenses
    for lic in licenses.iter() {
        let key = license_key(lic).ok_or("invalid license key")?;
        reinstate_license(key)?;
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(().into())
        .unwrap())
}

/// Handles cancellation of subscriptions.
///
/// A cancellation occurs either because the user explicitly cancelled the subscription,
/// or because they did not pay the monthly fee.
///
/// This will suspend all licenses associated with the order.
fn handle_subscription_cancelled(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    debug!("handle_subscription_cancelled");
    // first, authentify request from sendowl
    if !sendowl_authentify_web_hook(&req) {
        // Wrong signature
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let order_json = body_to_json(req.body())?;
    let licenses = licenses_from_order(&order_json)?;

    // revoke all licenses
    for lic in licenses.iter() {
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
        .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_PRODUCT_TOKEN))
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

/// Handles license creation requests (coming from SendOwl).
/// A new license will be created for the product_id and policy_id passed in the URL parameters.
/// The generated license has no expiration date: they are explicitly revoked via a SendOwl web hook
/// (see [handle_subscription_cancelled]) when the subscription is cancelled.
fn handle_keygen_create(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    // first, authentify request from sendowl
    if !sendowl_verify_signed_url(&req) {
        // Wrong signature
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    // get product ID and policy ID and order ID
    let params = req.query_string_parameters();
    let policy_id = params.get("policy_id").ok_or("invalid query parameters")?;
    let order_id = params.get("order_id").ok_or("invalid query parameters")?;

    //-------------------------------------------
    // create license

    // 16-byte random number, hex encoded
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
                    "sendOwlOrderId": order_id
                }
            },
            "relationships": {
                "policy": {
                    "data": { "type": "policies", "id": policy_id }
                }
            }
        }
    });

    let client = reqwest::Client::new();
    let reply: serde_json::Value = client
        .post(&format!(
            "https://api.keygen.sh/v1/accounts/{}/licenses",
            *KEYGEN_ACCOUNT_ID
        ))
        .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_PRODUCT_TOKEN))
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
        .header(AUTHORIZATION, format!("Bearer {}", *KEYGEN_PRODUCT_TOKEN))
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

    //

    // return activation code (activation token + license key)
    let code = format!("{}.{}", activation_token, license_key);
    //let code = base64::encode(&code[..]);

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(code.into())
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
