use axum::extract::{Path, Query, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::{Extension, Json, middleware};
use axum::{Router, response::Html, routing::get};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tower_http::services::ServeDir;

struct MyCounter {
    counter: AtomicUsize,
}
struct MyConfig {
    text: String,
}
struct MyLocalState(i32);

fn service_one() -> Router {
    let state = Arc::new(MyLocalState(5));
    Router::new().route("/", get(sv1_handler)).with_state(state)
}

async fn sv1_handler(
    Extension(counter): Extension<Arc<MyCounter>>,
    State(state): State<Arc<MyLocalState>>,
) -> Html<String> {
    counter
        .counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Html(format!(
        "<h1>Service 1: {}, state: {}</h1>",
        counter.counter.load(std::sync::atomic::Ordering::Relaxed),
        state.0
    ))
}

#[tokio::main]
async fn main() {
    let shared_counter = Arc::new(MyCounter {
        counter: AtomicUsize::new(0),
    });
    let shared_text = Arc::new(MyConfig {
        text: "This is my configuration 2".to_string(),
    });

    let other = Router::new().route("/other", get(path_extract));

    let app = Router::new()
        .route("/", get(header_handler))
        .route("/handler", get(handler))
        .route_layer(middleware::from_fn(auth))
        .nest("/1", service_one())
        .route("/handler_impl", get(handler_impl))
        .route("/book/{id}", get(path_extract))
        .route("/book", get(query_extract))
        .route("/header", get(header_extract))
        .route("/inc", get(increment))
        .route("/get_inc", get(handler_request))
        .route("/status", get(handler_status_code))
        .fallback_service(ServeDir::new("web"))
        .layer(Extension(shared_counter))
        .layer(Extension(shared_text))
        .merge(other);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    tokio::spawn(make_request());

    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn increment(Extension(counter): Extension<Arc<MyCounter>>) -> Json<usize> {
    println!("/inc service called");
    let value = counter
        .counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Json(value)
}

async fn handler(
    Extension(counter): Extension<Arc<MyCounter>>,
    Extension(config): Extension<Arc<MyConfig>>,
) -> Html<String> {
    counter
        .counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Html(format!(
        "<h1>{} You are visitor number {}</h1>",
        config.text,
        counter.counter.load(std::sync::atomic::Ordering::Relaxed)
    ))
}

async fn path_extract(Path(id): Path<u32>) -> Html<String> {
    Html(format!("hello, {id}"))
}

async fn query_extract(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    Html(format!("hello, {params:#?}"))
}

async fn header_extract(headers: HeaderMap) -> Html<String> {
    Html(format!("hello, {headers:#?}"))
}

async fn handler_request() -> Html<String> {
    println!("Sending Get request");
    let current_count = reqwest::get("http://localhost:3001/inc")
        .await
        .unwrap()
        .json::<i32>()
        .await
        .unwrap();

    Html(format!("<h1>{current_count}</h1>"))
}
async fn handler_status_code() -> StatusCode {
    StatusCode::IM_A_TEAPOT
}

async fn handler_impl() -> Result<impl IntoResponse, StatusCode> {
    let strat = std::time::SystemTime::now();
    let seconds_wrapped = strat
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs()
        % 3; // выполняет каждые 3 секунды

    let devided = 100u64
        .checked_div(seconds_wrapped)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(devided))

    // if 1 == 1 {
    //     Ok(Json(32))
    // } else {
    //     Err(StatusCode::BAD_REQUEST)
    // }
}

async fn make_request() {
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let response = reqwest::Client::new()
        .get("http://localhost:3001/")
        .header("x-request-id", "1234")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("{}", response);

    let response = reqwest::Client::new()
        .get("http://localhost:3001/")
        .header("x-request-id", "bad")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("{}", response);
}

#[derive(Clone)]
struct AuthHeader {
    id: String,
}

async fn auth(
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(header) = headers.get("x-request-id") {
        let header = header.to_str().unwrap();
        if header == "1234" {
            req.extensions_mut().insert(AuthHeader {
                id: header.to_string(),
            });
            return Ok(next.run(req).await);
        }
    }

    Err((StatusCode::UNAUTHORIZED, "Invalid header".to_string()))
}

async fn header_handler(Extension(auth): Extension<AuthHeader>, header: HeaderMap) -> Html<String> {
    if let Some(header) = header.get("x-request-id") {
        Html(format!(
            "<h1>Header x-request-id: {:?}, id: {:?}</h1>",
            header, auth.id
        ))
    } else {
        Html("<h1>Header x-request-id: None</h1>".to_string())
    }
}
