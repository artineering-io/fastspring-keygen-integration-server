use lambda_http::Request;
use log::{debug, error, info};
use hmac::{Hmac, Mac, NewMac};
use other_md5::Md5;
use lazy_static::lazy_static;
use std::env;

type HmacMd5 = Hmac<Md5>;

lazy_static! {
    static ref PATREON_WEBHOOK_SECRET: String = env::var("PATREON_WEBHOOK_SECRET").unwrap();
}

pub fn authentify_web_hook(req: &Request) -> bool {
    // get auth header
    let signature = if let Some(h) = req
        .headers()
        .get("X-Patreon-Signature")
        .and_then(|h| h.to_str().ok())
    {
        hex::decode(h).expect("invalid patreon signature format")
    } else {
        error!("patreon::authentify_web_hook: unable to authentify web hook");
        return false;
    };

    let mut mac : HmacMd5 = HmacMd5::new_varkey(PATREON_WEBHOOK_SECRET.as_bytes()).unwrap();
    mac.update(req.body().as_ref());

    match mac.verify(&signature) {
        Ok(_) => {
            return true;
        }
        Err(e) => {
            error!("authentify_web_hook: signature check failed {}", e);
            return false;
        }
    }
}