mod auth;
mod engine;
mod gateway;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, State,
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gateway::{Gateway, IndexedLog};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::broadcast};

#[derive(Clone)]
struct Shared {
    gateway: Arc<Mutex<Gateway>>,
    operator: Option<[u8; 32]>,
}
fn origin(headers: &HeaderMap) -> Option<&str> {
    headers.get("origin").and_then(|v| v.to_str().ok())
}
fn headers(response: &mut Response, origin: Option<&str>) {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("vary", "Origin"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    if let Some(origin) = origin {
        response.headers_mut().insert(
            "access-control-allow-origin",
            HeaderValue::from_str(origin).unwrap(),
        );
        response.headers_mut().insert(
            "access-control-allow-methods",
            HeaderValue::from_static("POST, OPTIONS"),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            HeaderValue::from_static("content-type"),
        );
    }
}
async fn rpc(
    State(s): State<Shared>,
    Path(secret): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let id = auth::key_id(&secret);
    let origin = origin(&h);
    let mut g = s.gateway.lock().unwrap();
    let authorized = g.session(id, origin).is_ok();
    let result = if let Some(batch) = body.as_array() {
        if batch.is_empty() || batch.len() > 32 {
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}})
        } else {
            Value::Array(batch.iter().map(|r| g.process(id, origin, r)).collect())
        }
    } else {
        g.process(id, origin, &body)
    };
    let mut response = Json(result).into_response();
    headers(&mut response, if authorized { origin } else { None });
    response
}
async fn preflight(State(s): State<Shared>, Path(secret): Path<String>, h: HeaderMap) -> Response {
    let authorized = s
        .gateway
        .lock()
        .unwrap()
        .session(auth::key_id(&secret), origin(&h))
        .is_ok();
    let mut r = if authorized {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::FORBIDDEN
    }
    .into_response();
    headers(&mut r, if authorized { origin(&h) } else { None });
    r
}
async fn ws(
    State(s): State<Shared>,
    Path(secret): Path<String>,
    h: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let id = auth::key_id(&secret);
    let origin = origin(&h).map(str::to_owned);
    // Subscribe under the same lock as auth/state so no commit is missed.
    let receiver = {
        let g = s.gateway.lock().unwrap();
        if g.session(id, origin.as_deref()).is_err() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        g.changes.subscribe()
    };
    upgrade
        .max_message_size(128 * 1024)
        .max_frame_size(128 * 1024)
        .on_upgrade(move |socket| subscription(socket, s, id, origin, receiver))
        .into_response()
}
async fn subscription(
    mut socket: WebSocket,
    s: Shared,
    id: [u8; 32],
    origin: Option<String>,
    mut receiver: broadcast::Receiver<Vec<IndexedLog>>,
) {
    let mut active: Option<(String, Value)> = None;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        // Expiry/revocation applies even while the chain is idle.
        if s.gateway
            .lock()
            .unwrap()
            .session(id, origin.as_deref())
            .is_err()
        {
            let _ = socket.send(Message::Close(None)).await;
            break;
        }
        tokio::select! {
            _=tick.tick()=>{},
            msg=socket.recv()=>{
                let Some(Ok(Message::Text(text)))=msg else {break;};
                let response={
                    let g=s.gateway.lock().unwrap();
                    let req:Value=serde_json::from_str(&text).unwrap_or(Value::Null);
                    let valid=g.session(id,origin.as_deref()).ok().is_some_and(|session|
                        req["jsonrpc"]=="2.0" && req["method"]=="eth_subscribe" && req["params"][0]=="logs"
                        && g.validate_filter(&session,&req["params"][1]).is_ok());
                    if valid && active.is_none() {
                        let subscription=auth::secret();active=Some((subscription.clone(),req["params"][1].clone()));
                        json!({"jsonrpc":"2.0","id":req["id"],"result":subscription})
                    } else {json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":4100,"message":"Unauthorized"}})}
                };
                if socket.send(Message::Text(response.to_string().into())).await.is_err(){break;}
            },
            events=receiver.recv()=>{
                let Ok(events)=events else {let _=socket.send(Message::Close(None)).await;break;};
                if let Some((subscription,filter))=&active {
                    // Reauthorize each delivery; no unfiltered events leave this process.
                    for event in events {
                        let visible={let g=s.gateway.lock().unwrap();g.session(id,origin.as_deref()).ok().is_some_and(|session|g.visible(&session,&event,filter))};
                        if visible {
                            let response=json!({"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":subscription,"result":event.json()}});
                            if socket.send(Message::Text(response.to_string().into())).await.is_err(){return;}
                        }
                    }
                }
            }
        }
    }
}
async fn public_rpc(Json(body): Json<Value>) -> Json<Value> {
    Json(if body["method"] == "eth_chainId" {
        json!({"jsonrpc":"2.0","id":body["id"],"result":format!("0x{:x}",engine::CHAIN_ID)})
    } else {
        json!({"jsonrpc":"2.0","id":body["id"],"error":{"code":4100,"message":"Unauthorized"}})
    })
}
async fn operator(State(s): State<Shared>, Path(secret): Path<String>) -> StatusCode {
    if s.operator != Some(auth::key_id(&secret)) {
        return StatusCode::UNAUTHORIZED;
    }
    if s.gateway.lock().unwrap().rollback().is_ok() {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    }
}
async fn config(State(s): State<Shared>) -> Json<Value> {
    Json(s.gateway.lock().unwrap().public_config())
}
async fn ethers() -> Response {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("node_modules/ethers/dist/ethers.min.js");
    match std::fs::read_to_string(path) {
        Ok(js) => ([("content-type", "text/javascript")], js).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Run npm ci in demos/privacy-rpc first",
        )
            .into_response(),
    }
}
fn js(text: &'static str) -> impl IntoResponse {
    ([("content-type", "text/javascript")], text)
}
async fn bind(var: &str, default: u16) -> TcpListener {
    let port = std::env::var(var)
        .ok()
        .map(|p| p.parse().unwrap())
        .unwrap_or(default);
    TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap()
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let credentials = args
        .windows(2)
        .find(|v| v[0] == "--credentials")
        .map(|v| PathBuf::from(&v[1]))
        .expect("--credentials PATH is required (new private file)");
    let test_controls = args.iter().any(|v| v == "--test-controls");
    let rpc_listener = bind("PORT", 9000).await;
    let a = bind("APP_A_PORT", 9001).await;
    let b = bind("APP_B_PORT", 9002).await;
    let base = format!("http://{}", rpc_listener.local_addr().unwrap());
    let origins = [
        format!("http://{}", a.local_addr().unwrap()),
        format!("http://{}", b.local_addr().unwrap()),
    ];
    let (gateway, mut private) = Gateway::new(base.clone(), origins.clone());
    let operator_secret = test_controls.then(auth::secret);
    if let Some(secret) = &operator_secret {
        private["operatorUrl"] = json!(format!("{base}/operator/{secret}"));
    }
    let shared = Shared {
        gateway: Arc::new(Mutex::new(gateway)),
        operator: operator_secret.as_deref().map(auth::key_id),
    };
    let main = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/wallet.html")) }),
        )
        .route(
            "/wallet.js",
            get(|| async { js(include_str!("../web/wallet.js")) }),
        )
        .route("/ethers.js", get(ethers))
        .route("/config", get(config))
        .route("/rpc", post(public_rpc))
        .route("/rpc/{secret}", post(rpc).options(preflight))
        .route("/rpc/{secret}/ws", get(ws))
        .route("/operator/{secret}", post(operator))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(shared);
    let app = |name: &str, index: usize| {
        let mut public = private["public"].clone();
        public["name"] = json!(name);
        public["tokenIndex"] = json!(index);
        public["rpcBase"] = json!(base);
        Router::new()
            .route("/", get(|| async { Html(include_str!("../web/app.html")) }))
            .route(
                "/app.js",
                get(|| async { js(include_str!("../web/app.js")) }),
            )
            .route(
                "/sdk.js",
                get(|| async { js(include_str!("../web/sdk.js")) }),
            )
            .route(
                "/config",
                get(move || {
                    let c = public.clone();
                    async { Json(c) }
                }),
            )
    };
    let app_a = app("Payments", 0);
    let app_b = app("Rewards", 1);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&credentials)
        .expect("create credentials file")
        .write_all(serde_json::to_string_pretty(&private).unwrap().as_bytes())
        .unwrap();
    println!(
        "Local privacy demo ready. Private credentials: {}",
        credentials.display()
    );
    let _ = tokio::join!(
        axum::serve(rpc_listener, main),
        axum::serve(a, app_a),
        axum::serve(b, app_b)
    );
}
