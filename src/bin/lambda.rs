use dotenv;
use fastspring_keygen_integration::fastspring;
use fastspring_keygen_integration::keygen;
use fastspring_keygen_integration::keygen::{generate_licenses, suspend_license};
use fastspring_keygen_integration::util;
use fastspring_keygen_integration::patreon;
use http::header::CONTENT_TYPE;
use lambda_http::{lambda, Body, Request, RequestExt, Response};
use lambda_runtime::error::HandlerError;
use lambda_runtime::Context;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::env;
use lazy_static::lazy_static;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

lazy_static! {
    static ref MNPRX_COMMUNITY_KEYGEN_POLICY_ID: String = env::var("MNPRX_COMMUNITY_KEYGEN_POLICY_ID").unwrap();
    static ref SMTP_SERVER: String = env::var("SMTP_SERVER").unwrap();
    static ref SMTP_USERNAME: String = env::var("SMTP_USERNAME").unwrap();
    static ref SMTP_PASSWORD: String = env::var("SMTP_PASSWORD").unwrap();
}

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
        "/fastspring-keygen-integration-service/patreon" => match *req.method() {
            http::Method::POST => handle_patreon_webhook(&client, req, c),
            _ => not_allowed(req, c),
        },
        _ => not_found(req, c),
    }
}

fn license_key(code: &str) -> Option<&str> {
    code.split('.').nth(1)
}

fn handle_patreon_webhook(
    client: &reqwest::Client,
    req: Request,
    _c: Context,
) -> Result<Response<Body>, HandlerError>
{
    if !patreon::authentify_web_hook(&req) {
        return Ok(Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body(Body::default())
            .unwrap());
    }

    let trigger = req.headers().get("X-Patreon-Event")
        .ok_or("invalid format (X-Patreon-Event)")?
        .to_str().ok().ok_or("invalid format (X-Patreon-Event)")?;

    debug!("X-Patreon-Event: {}", trigger);
    let body = util::body_to_json(req.body())?;

    if trigger == "pledges:create" {
        patreon_handle_pledge_create(client, &body)?;
    } else if trigger == "pledges:delete" {
        patreon_handle_pledge_delete(client, &body)?;
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(Body::default())
        .unwrap())
}

/// Patreon pledge create trigger
fn patreon_handle_pledge_create(
    client: &reqwest::Client,
    body: &serde_json::Value,
) -> Result<Response<Body>, HandlerError>
{
    debug!("handle_pledge_create {:?}", body);

    let user_id = body["data"]["relationships"]["patron"]["data"]["id"].as_str().ok_or("invalid format (.data.patron.data.id)")?;

    let mut user_email = None;
    for included in body["included"].as_array().ok_or("invalid format (.included)")?.iter() {
        if included["id"].as_str().ok_or("invalid format (.included.#.id)")? == user_id {
            user_email = Some(included["attributes"]["email"].as_str().ok_or("invalid format (.included.#.attributes.email)")?);
        }
    }

    let user_email = user_email.ok_or("could not find patron email")?;

    debug!("patron email: {}", user_email);

    let license=
        keygen::generate_license(
            client,
            "PATREON",
            MNPRX_COMMUNITY_KEYGEN_POLICY_ID.as_ref(),
            None,
            Some(user_id),
            false)?;

    // send the license to the patron
    let email = Message::builder()
        .from("Artineering <hello@artineering.io>".parse().unwrap())
        .reply_to("Artineering <hello@artineering.io>".parse().unwrap())
        .to(user_email.parse().unwrap())
        .subject("Your license key for MNPRX Community")
        .body(format!("Use the following license key: {}", license))
        .unwrap();

    let creds = Credentials::new(SMTP_USERNAME.clone(), SMTP_PASSWORD.clone());

    let mailer = SmtpTransport::relay(SMTP_SERVER.as_ref())
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => info!("Email sent successfully"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(().into())
        .unwrap())
}

/// Patreon pledge delete trigger
fn patreon_handle_pledge_delete(
    client: &reqwest::Client,
    data: &serde_json::Value,
) -> Result<Response<Body>, HandlerError>
{
    debug!("handle_pledge_delete {:?}", data);

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(().into())
        .unwrap())
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
    info!("subscription deactivated: {}", subscription_id);

    let orders = fastspring::get_subscription_entries(client, subscription_id)?;

    // find the original order
    // according to the API, this is the entry whose ".reference" field does not include
    // a "B" (for "billing") at the end. All the others are subscription billing orders.
    let original_order = orders.as_array().ok_or("invalid format (orders)")?.iter().find(|&order| {
        let order = &order["order"];
        if order["reference"].is_null() { return false; }
        if let Some(s) = order["reference"].as_str() {
            !s.ends_with('B')
        } else {
            false
        }
    });

    let original_order = original_order.ok_or("could not find original order")?;
    let order_items = original_order["order"]["items"]
        .as_array()
        .ok_or("invalid format (.order.items)")?;

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
                    let code = if let Some(s) = l["license"].as_str() {
                        s
                    } else {
                        continue;
                    };
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

    let (codes,errors) = generate_licenses(subscription, policy_id, quantity, None, false);
    if !errors.is_empty() {
        Err(format!("errors encountered while generating licenses ({} successfully generated)", codes.len()).as_str())?
    }

    let codes = codes.join("\n");

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
    env_logger::init();
    dotenv::dotenv().ok();
    lambda!(router);
    Ok(())
}
