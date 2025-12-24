mod connection_test;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post, patch},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use mongodb::{Client, bson::{doc, Document}};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use rand_core::OsRng;
use mongodb::options::IndexOptions;
use mongodb::IndexModel;
use std::collections::HashMap;
use axum::extract::Query;

#[derive(Clone)]
struct AppState {
    db: mongodb::Database,
}

#[tokio::main]
async fn main() {
    // connect to MongoDB
    let client: Client = Client::with_uri_str("mongodb://localhost:27017").await.unwrap();
    let db = client.database("StarTechDB");
    let state = Arc::new(AppState { db });

    ensure_indexes(&state.db).await.expect("index creation failed");

    // CORS for Vue dev server (change origin if needed)
    let cors = CorsLayer::new()
        .allow_origin(["http://localhost:5173".parse().unwrap()])
        .allow_methods(Any)
        .allow_headers(Any);

    // build routes
    let app = Router::new()
        .route("/", get(root))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/user", get(get_user))
        .route("/user", patch(update_user)) // add this
        .with_state(state)
        .layer(cors);

    // start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn ensure_indexes(db: &mongodb::Database) -> mongodb::error::Result<()> {
    let users = db.collection::<Document>("users");
    let mut opts = IndexOptions::default();
    opts.unique = Some(true);
    opts.name = Some("uniq_email".into());
    let model = IndexModel::builder()
        .keys(doc! { "email": 1 })
        .options(opts)
        .build();
    users.create_index(model, None).await?;
    Ok(())
}

async fn root() -> &'static str {
    "API running"
}

#[derive(Deserialize)]
struct SignupRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct ApiResponse {
    message: String,
}

async fn signup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignupRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let users = state.db.collection::<Document>("users");

    // check uniqueness
    if users.find_one(doc! { "email": &payload.email }, None).await.unwrap().is_some() {
        return (StatusCode::CONFLICT, Json(ApiResponse { message: "Email already registered".into() }));
    }

    // hash password
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // store user
    let now = chrono::Utc::now().to_rfc3339();
    let doc = doc! {
        "name": payload.name,
        "email": payload.email,
        "password": hashed,
        "date": now,
    };
    users.insert_one(doc, None).await.unwrap();

    (StatusCode::CREATED, Json(ApiResponse { message: "User created".into() }))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    message: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    let users = state.db.collection::<Document>("users");

    let user = match users.find_one(doc! { "email": &payload.email }, None).await {
        Ok(doc) => doc,
        Err(e) => {
            eprintln!("find_one error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(LoginResponse { message: "Server error".into() }));
        }
    };

    // email not found
    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, Json(LoginResponse { message: "Invalid credentials".into() }));
    };

    // get stored hash
    let Ok(stored) = user.get_str("password") else {
        return (StatusCode::UNAUTHORIZED, Json(LoginResponse { message: "Invalid credentials".into() }));
    };

    // verify only argon2 hashes
    if stored.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(stored) {
            if Argon2::default().verify_password(payload.password.as_bytes(), &parsed).is_ok() {
                return (StatusCode::OK, Json(LoginResponse { message: "Login successful".into() }));
            }
        }
    }

    (StatusCode::UNAUTHORIZED, Json(LoginResponse { message: "Invalid credentials".into() }))
}

#[derive(Serialize)]
struct UserResponse {
    name: Option<String>,
    email: Option<String>,
    message: Option<String>,
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<UserResponse>) {
    let email = match params.get("email") {
        Some(e) if !e.trim().is_empty() => e.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(UserResponse {
                    name: None,
                    email: None,
                    message: Some("missing email query parameter".into()),
                }),
            )
        }
    };

    let users = state.db.collection::<Document>("users");
    match users.find_one(doc! { "email": &email }, None).await {
        Ok(Some(doc)) => {
            let name = doc.get_str("name").ok().map(|s| s.to_string());
            let email = doc.get_str("email").ok().map(|s| s.to_string());
            (StatusCode::OK, Json(UserResponse { name, email, message: None }))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(UserResponse {
                name: None,
                email: None,
                message: Some("User not found".into()),
            }),
        ),
        Err(e) => {
            eprintln!("db error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserResponse {
                    name: None,
                    email: None,
                    message: Some("server error".into()),
                }),
            )
        }
    }
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    email: String,
    name: String,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateUserRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let users = state.db.collection::<Document>("users");
    match users
        .update_one(doc! { "email": &payload.email }, doc! { "$set": { "name": &payload.name } }, None)
        .await
    {
        Ok(res) => {
            if res.matched_count == 0 {
                return (StatusCode::NOT_FOUND, Json(ApiResponse { message: "User not found".into() }));
            }
            (StatusCode::OK, Json(ApiResponse { message: "Profile updated".into() }))
        }
        Err(e) => {
            eprintln!("update_user error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { message: "Update failed".into() }))
        }
    }
}