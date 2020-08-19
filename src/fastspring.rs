use lambda_http::{Body, Request};
use lambda_runtime::error::HandlerError;
use lazy_static::lazy_static;
use log::{debug, error, info};
use std::collections::HashMap;
use std::env;

lazy_static! {
    static ref FASTSPRING_API_USERNAME: String = env::var("FASTSPRING_API_USERNAME").unwrap();
    static ref FASTSPRING_API_PASSWORD: String = env::var("FASTSPRING_API_PASSWORD").unwrap();
    static ref FASTSPRING_WEBHOOK_SECRET: String = env::var("FASTSPRING_WEBHOOK_SECRET").unwrap();
    static ref FASTSPRING_LICENSE_GEN_PRIVATE_KEY: String =
        env::var("FASTSPRING_LICENSE_GEN_PRIVATE_KEY").unwrap();
}

pub fn verify_license_gen(req: &Request) -> bool {
    // collect query parameters
    let mut sig = "";
    let mut p = Vec::new();
    let params: HashMap<_, _> = url::form_urlencoded::parse(match req.body() {
        Body::Text(ref s) => s.as_bytes(),
        _ => return false,
    })
    .collect();

    for (k, v) in params.iter() {
        if k == "security_request_hash" {
            sig = v.as_ref();
        } else {
            p.push((k, v));
        }
    }
    // sort by key
    p.sort();

    // print query string
    let mut qstr = String::new();
    for i in 0..p.len() {
        qstr.push_str(p[i].1);
    }
    // append private key
    qstr.push_str(&*FASTSPRING_LICENSE_GEN_PRIVATE_KEY);

    // MD5 hash
    let digest = md5::compute(qstr.as_bytes());
    let digest = format!("{:032x}", digest);
    debug!("sig={}, digest={}", sig, &digest[..]);

    // compare
    let ok = sig == &digest[..];
    if ok {
        info!("verify_license_gen: authenticated request from FastSpring");
    } else {
        error!("verify_license_gen: signature check failed");
    }
    ok
}

pub fn authentify_web_hook(req: &Request) -> bool {
    // get auth header
    let hash = if let Some(h) = req
        .headers()
        .get("X-FS-Signature")
        .and_then(|h| h.to_str().ok())
    {
        h.to_owned()
    } else {
        error!("authentify_web_hook: unable to authentify web hook");
        return false;
    };

    let calc_hash = base64::encode(&hmac_sha256::HMAC::mac(
        req.body(),
        FASTSPRING_WEBHOOK_SECRET.as_bytes(),
    ));

    debug!(
        "authentify_web_hook: hash={}, calc_hash={}",
        hash, calc_hash
    );
    // compare with header
    let ok = hash == calc_hash;
    if ok {
        info!("authentify_web_hook: authenticated web hook from FastSpring");
    } else {
        error!("authentify_web_hook: signature check failed");
    }
    ok
}

/// Returns subscription info
pub fn get_subscription_entries(
    client: &reqwest::Client,
    id: &str,
) -> Result<serde_json::Value, HandlerError> {
    let reply = client
        .get(&format!(
            "https://api.fastspring.com/subscriptions/{}/entries",
            id
        ))
        .basic_auth(&*FASTSPRING_API_USERNAME, Some(&*FASTSPRING_API_PASSWORD))
        .send()
        .map_err(|_| "request error")?
        .json()
        .map_err(|_| "invalid json")?;

    Ok(reply)
}
