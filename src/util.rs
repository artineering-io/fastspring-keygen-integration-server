use lambda_http::Body;
use lambda_runtime::error::HandlerError;
use serde_json::Value;

pub fn body_to_json(body: &Body) -> Result<Value, HandlerError> {
    Ok(serde_json::from_str(match body {
        Body::Text(ref s) => s,
        _ => return Err("invalid json".into()),
    })
    .map_err(|_| "invalid json")?)
}
