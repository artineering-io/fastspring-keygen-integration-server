use crate::keygen::{generate_licenses, suspend_license};
use dotenv;
use http::header::CONTENT_TYPE;
use lambda_http::{lambda, Body, Request, RequestExt, Response};
use lambda_runtime::error::HandlerError;
use lambda_runtime::Context;
use log::{debug, warn};
use std::collections::HashMap;
use std::error::Error;

mod fastspring;
mod keygen;
mod util;

fn router(req: Request, c: Context) -> Result<Response<Body>, HandlerError> {
    debug!("router request={:?}", req);
    debug!("path={:?}", req.uri().path());
    debug!("query={:?}", req.query_string_parameters());

    let client = reqwest::Client::new();

    match req.uri().path() {
        "/fastspring-keygen-integration-service/keygen/create" => match *req.method() {
            http::Method::POST => handle_keygen_create(req, c),
            _ => not_allowed(req, c),
        },
        "/fastspring-keygen-integration-service/webhooks" => match *req.method() {
            http::Method::POST => handle_webhook(&client, req, c),
            _ => not_allowed(req, c),
        },
        _ => not_found(req, c),
    }
}

fn license_key(code: &str) -> Option<&str> {
    code.split('.').nth(1)
}

fn handle_webhook(
    client: &reqwest::Client,
    req: Request,
    _c: Context,
) -> Result<Response<Body>, HandlerError> {
    if !fastspring::authentify_web_hook(&req) {
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let events_json = util::body_to_json(req.body())?;
    let events_json = events_json["events"].as_array().ok_or("invalid format")?;

    // TODO do not reply OK every time: check each event
    for e in events_json {
        let ty = e["type"].as_str().ok_or("invalid format")?;
        let data = &e["data"];
        match ty {
            "subscription.deactivated" => {
                handle_subscription_deactivated(client, data)?;
            }
            _ => {
                warn!("unhandled webhook: {}", ty);
            }
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
fn handle_subscription_deactivated(
    client: &reqwest::Client,
    data: &serde_json::Value,
) -> Result<Response<Body>, HandlerError> {
    debug!("handle_subscription_deactivated {:?}", data);

    let subscription_id = data["id"].as_str().ok_or("invalid format (.id)")?;
    debug!("subscription deactivated: {}", subscription_id);

    let order = fastspring::get_subscription_entries(client, subscription_id)?;
    let order_items = order[0]["order"]["items"]
        .as_array()
        .ok_or("invalid format (.[0].order.items)")?;

    // Collect all licenses to revoke
    let mut licenses_to_revoke = Vec::new();
    for item in order_items.iter() {
        //let product = &item["product"];
        for (_k, v) in item["fulfillments"]
            .as_object()
            .ok_or("invalid format (.fulfillments)")?
            .iter()
        {
            if let Some(licenses) = v.as_array() {
                for l in licenses {
                    let code = if let Some(s) = l["license"].as_str() { s } else { continue };
                    licenses_to_revoke.push(String::from(code));
                }
            }
        }
    }

    // revoke all licenses
    for lic in licenses_to_revoke.iter() {
        let key = license_key(lic).ok_or("invalid license key")?;
        keygen::revoke_license(key)?;
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(().into())
        .unwrap())
}

/// Handles license creation requests (coming from FastSpring).
fn handle_keygen_create(req: Request, _c: Context) -> Result<Response<Body>, HandlerError> {
    if !fastspring::verify_license_gen(&req) {
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let params: HashMap<_, _> = url::form_urlencoded::parse(match req.body() {
        Body::Text(ref s) => s.as_bytes(),
        _ => return Err("invalid request body".into()),
    })
    .collect();
    //debug!("params = {:?}", params);
    let subscription = params
        .get("subscription")
        .ok_or("invalid query parameters (no subscription)")?;
    let policy_id = params
        .get("policy")
        .ok_or("invalid query parameters (no policy)")?;
    let quantity: u32 = params
        .get("quantity")
        .ok_or("invalid query parameters (no quantity)")?
        .parse()?;

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
