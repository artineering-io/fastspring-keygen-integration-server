use lambda_http::{Request};
use lazy_static::lazy_static;
use log::{debug,warn,error};
use std::env;
use lambda_runtime::error::HandlerError;


lazy_static! {
    //static ref FASTSPRING_API_KEY: String = env::var("FASTSPRING_API_KEY").unwrap();
    static ref FASTSPRING_API_USERNAME: String = env::var("FASTSPRING_API_USERNAME").unwrap();
    static ref FASTSPRING_API_PASSWORD: String = env::var("FASTSPRING_API_PASSWORD").unwrap();
    static ref FASTSPRING_SIGNING_KEY: String = env::var("FASTSPRING_SIGNING_KEY").unwrap();
    static ref FASTSPRING_SIGNING_KEY_SECRET: String = env::var("FASTSPRING_SIGNING_KEY_SECRET").unwrap();
}


pub fn verify_signed_url(req: &Request) -> bool {
    true
    /*// collect query parameters
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
    ok*/
}

pub fn authentify_web_hook(req: &Request) -> bool {
    true
    /*// get auth header
    let hash = if let Some(h) = req.headers().get("X-SENDOWL-HMAC-SHA256").and_then(|h| h.to_str().ok()) {
        h.to_owned()
    } else {
        error!("Unable to authentify web hook request");
        return false
    };

    let calc_hash = base64::encode(&hmac_sha256::HMAC::mac(req.body(), FASTSPRING_SIGNING_KEY_SECRET.as_bytes()));

    debug!("hash={}, calc_hash={}", hash, calc_hash);
    // compare with header
    hash == calc_hash*/
}


/// Returns subscription info
pub fn get_subscription_entries(client: &reqwest::Client, id: &str) -> Result<serde_json::Value, HandlerError>
{
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