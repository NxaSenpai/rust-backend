mod connection_test;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post, patch, delete},
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
use axum::extract::{Query, Path};
use futures::stream::TryStreamExt;
use mongodb::bson::oid::ObjectId;

#[derive(Clone)]
struct AppState {
    db: mongodb::Database,
}

#[tokio::main]
async fn main() {
    let client: Client = Client::with_uri_str("mongodb://localhost:27017").await.unwrap();
    let db = client.database("StarTechDB");
    let state = Arc::new(AppState { db });

    ensure_indexes(&state.db).await.expect("index creation failed");

    let cors = CorsLayer::new()
        .allow_origin(["http://localhost:5173".parse().unwrap()])
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/user", get(get_user))
        .route("/user", patch(update_user))
        .route("/categories", get(get_categories))
        .route("/categories", post(create_category))
        .route("/categories/:id", patch(update_category))
        .route("/categories/:id", delete(delete_category))
        .route("/categories/bulk-delete", post(bulk_delete_categories))
        .route("/suppliers", get(get_suppliers))
        .route("/suppliers", post(create_supplier))
        .route("/suppliers/:id", patch(update_supplier))
        .route("/suppliers/:id", delete(delete_supplier))
        .route("/suppliers/bulk-delete", post(bulk_delete_suppliers))
        .with_state(state)
        .layer(cors);

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
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "user".to_string()
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

    if users.find_one(doc! { "email": &payload.email }, None).await.unwrap().is_some() {
        return (StatusCode::CONFLICT, Json(ApiResponse { message: "Email already registered".into() }));
    }

    let role = match payload.role.to_lowercase().as_str() {
        "admin" | "superadmin" => payload.role.to_lowercase(),
        _ => "user".to_string(),
    };

    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let now = chrono::Utc::now().to_rfc3339();
    let doc = doc! {
        "name": payload.name,
        "email": payload.email,
        "password": hashed,
        "role": role,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(LoginResponse { 
                message: "Server error".into(),
                name: None,
                email: None,
                role: None,
            }));
        }
    };

    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, Json(LoginResponse { 
            message: "Invalid credentials".into(),
            name: None,
            email: None,
            role: None,
        }));
    };

    let Ok(stored) = user.get_str("password") else {
        return (StatusCode::UNAUTHORIZED, Json(LoginResponse { 
            message: "Invalid credentials".into(),
            name: None,
            email: None,
            role: None,
        }));
    };

    if stored.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(stored) {
            if Argon2::default().verify_password(payload.password.as_bytes(), &parsed).is_ok() {
                
                let name = user.get_str("name").ok().map(|s| s.to_string());
                let email = user.get_str("email").ok().map(|s| s.to_string());
                let role = user.get_str("role").ok().map(|s| s.to_string()).unwrap_or_else(|| "user".to_string());
                
                println!("User logged in: {:?}, role: {}", name, role);
                
                return (StatusCode::OK, Json(LoginResponse { 
                    message: "Login successful".into(),
                    name,
                    email,
                    role: Some(role),
                }));
            }
        }
    }

    (StatusCode::UNAUTHORIZED, Json(LoginResponse { 
        message: "Invalid credentials".into(),
        name: None,
        email: None,
        role: None,
    }))
}

#[derive(Serialize)]
struct UserResponse {
    name: Option<String>,
    email: Option<String>,
    role: Option<String>,
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
                    role: None,
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
            let role = doc.get_str("role").ok().map(|s| s.to_string()).unwrap_or_else(|| "user".to_string());
            (StatusCode::OK, Json(UserResponse { name, email, role: Some(role), message: None }))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(UserResponse {
                name: None,
                email: None,
                role: None,
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
                    role: None,
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

#[derive(Serialize)]
struct CategoryResponse {
    #[serde(rename = "_id")]
    id: String,
    name: String,
    #[serde(rename = "productCount")]
    product_count: i32,
    status: String,
    #[serde(rename = "createdDate")]
    created_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Category {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    name: String,
    #[serde(rename = "productCount")]
    product_count: i32,
    status: String,
    #[serde(rename = "createdDate", skip_serializing_if = "Option::is_none")]
    created_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl Category {
    fn to_response(self) -> CategoryResponse {
        CategoryResponse {
            id: self.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: self.name,
            product_count: self.product_count,
            status: self.status,
            created_date: self.created_date.unwrap_or_else(|| "N/A".to_string()),
            description: self.description,
        }
    }
}

#[derive(Serialize)]
struct SupplierResponse {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "companyName")]
    company_name: String,
    #[serde(rename = "contactPerson")]
    contact_person: String,
    email: String,
    phone: String,
    #[serde(rename = "productCount")]
    product_count: i32,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "createdDate")]
    created_date: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Supplier {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    #[serde(rename = "companyName")]
    company_name: String,
    #[serde(rename = "contactPerson")]
    contact_person: String,
    email: String,
    phone: String,
    #[serde(rename = "productCount")]
    product_count: i32,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "createdDate", skip_serializing_if = "Option::is_none")]
    created_date: Option<String>,
}

impl Supplier {
    fn to_response(self) -> SupplierResponse {
        SupplierResponse {
            id: self.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            company_name: self.company_name,
            contact_person: self.contact_person,
            email: self.email,
            phone: self.phone,
            product_count: self.product_count,
            status: self.status,
            address: self.address,
            notes: self.notes,
            created_date: self.created_date.unwrap_or_else(|| "N/A".to_string()),
        }
    }
}

async fn get_categories(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<CategoryResponse>>) {
    println!("GET /categories called");
    let collection = state.db.collection::<Category>("categories");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            let categories: Vec<Category> = cursor.try_collect().await.unwrap_or_default();
            let response: Vec<CategoryResponse> = categories
                .into_iter()
                .map(|cat| cat.to_response())
                .collect();
            println!("Found {} categories", response.len());
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            eprintln!("get_categories error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn create_category(
    State(state): State<Arc<AppState>>,
    Json(mut payload): Json<Category>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating category: {:?}", payload);
    let collection = state.db.collection::<Category>("categories");
    
    payload.created_date = Some(chrono::Utc::now().format("%Y-%m-%d").to_string());
    payload.id = None;
    
    match collection.insert_one(&payload, None).await {
        Ok(result) => {
            println!("Category created with ID: {:?}", result.inserted_id);
            (StatusCode::CREATED, Json(ApiResponse { message: "Category created".into() }))
        }
        Err(e) => {
            eprintln!("create_category error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Failed to create category: {}", e) 
            }))
        }
    }
}

async fn update_category(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<Category>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("UPDATE /categories/{}", id);
    println!("Payload: {:?}", payload);
    
    let collection = state.db.collection::<Document>("categories");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => {
            println!("Parsed ObjectId successfully: {}", oid);
            oid
        },
        Err(e) => {
            eprintln!("Failed to parse ObjectId '{}': {:?}", id, e);
            return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
                message: format!("Invalid ID format: {}", e) 
            }));
        }
    };

    let update_doc = doc! {
        "$set": {
            "name": payload.name,
            "productCount": payload.product_count,
            "status": payload.status,
            "description": payload.description.unwrap_or_default(),
        }
    };

    match collection.update_one(doc! { "_id": oid }, update_doc, None).await {
        Ok(res) => {
            println!("Update result - matched: {}, modified: {}", res.matched_count, res.modified_count);
            if res.matched_count > 0 {
                (StatusCode::OK, Json(ApiResponse { message: "Category updated".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Category not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("update_category error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Update failed: {}", e) 
            }))
        }
    }
}

async fn delete_category(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /categories/{}", id);
    
    let collection = state.db.collection::<Document>("categories");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => {
            println!("Parsed ObjectId successfully: {}", oid);
            oid
        },
        Err(e) => {
            eprintln!("Failed to parse ObjectId '{}': {:?}", id, e);
            return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
                message: format!("Invalid ID format: {}", e) 
            }));
        }
    };

    match collection.delete_one(doc! { "_id": oid }, None).await {
        Ok(res) => {
            println!("Delete result - deleted: {}", res.deleted_count);
            if res.deleted_count > 0 {
                (StatusCode::OK, Json(ApiResponse { message: "Category deleted".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Category not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("delete_category error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Delete failed: {}", e) 
            }))
        }
    }
}

#[derive(Deserialize)]
struct BulkDeleteRequest {
    ids: Vec<String>,
}

async fn bulk_delete_categories(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("BULK DELETE - Received {} IDs", payload.ids.len());
    println!("IDs: {:?}", payload.ids);
    
    let collection = state.db.collection::<Document>("categories");
    
    let oids: Vec<ObjectId> = payload.ids
        .iter()
        .filter_map(|id| {
            match ObjectId::parse_str(id) {
                Ok(oid) => {
                    println!("Parsed ID: {} -> {:?}", id, oid);
                    Some(oid)
                }
                Err(e) => {
                    eprintln!("Failed to parse ID '{}': {:?}", id, e);
                    None
                }
            }
        })
        .collect();

    println!("Successfully parsed {} ObjectIds", oids.len());

    if oids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
            message: "No valid IDs provided".into() 
        }));
    }

    match collection.delete_many(doc! { "_id": { "$in": oids } }, None).await {
        Ok(res) => {
            println!("Bulk delete result - deleted: {}", res.deleted_count);
            (StatusCode::OK, Json(ApiResponse { 
                message: format!("{} categories deleted", res.deleted_count) 
            }))
        }
        Err(e) => {
            eprintln!("bulk_delete error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Bulk delete failed: {}", e) 
            }))
        }
    }
}

async fn get_suppliers(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<SupplierResponse>>) {
    println!("GET /suppliers called");
    let collection = state.db.collection::<Supplier>("suppliers");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            let suppliers: Vec<Supplier> = cursor.try_collect().await.unwrap_or_default();
            let response: Vec<SupplierResponse> = suppliers
                .into_iter()
                .map(|sup| sup.to_response())
                .collect();
            println!("Found {} suppliers", response.len());
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            eprintln!("get_suppliers error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn create_supplier(
    State(state): State<Arc<AppState>>,
    Json(mut payload): Json<Supplier>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating supplier: {:?}", payload);
    let collection = state.db.collection::<Supplier>("suppliers");
    
    payload.created_date = Some(chrono::Utc::now().format("%Y-%m-%d").to_string());
    payload.id = None;
    
    match collection.insert_one(&payload, None).await {
        Ok(result) => {
            println!("Supplier created with ID: {:?}", result.inserted_id);
            (StatusCode::CREATED, Json(ApiResponse { message: "Supplier created".into() }))
        }
        Err(e) => {
            eprintln!("create_supplier error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Failed to create supplier: {}", e) 
            }))
        }
    }
}

async fn update_supplier(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<Supplier>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("UPDATE /suppliers/{}", id);
    println!("Payload: {:?}", payload);
    
    let collection = state.db.collection::<Document>("suppliers");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => {
            println!("Parsed ObjectId successfully: {}", oid);
            oid
        },
        Err(e) => {
            eprintln!("Failed to parse ObjectId '{}': {:?}", id, e);
            return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
                message: format!("Invalid ID format: {}", e) 
            }));
        }
    };

    let update_doc = doc! {
        "$set": {
            "companyName": payload.company_name,
            "contactPerson": payload.contact_person,
            "email": payload.email,
            "phone": payload.phone,
            "productCount": payload.product_count,
            "status": payload.status,
            "address": payload.address.unwrap_or_default(),
            "notes": payload.notes.unwrap_or_default(),
        }
    };

    match collection.update_one(doc! { "_id": oid }, update_doc, None).await {
        Ok(res) => {
            println!("Update result - matched: {}, modified: {}", res.matched_count, res.modified_count);
            if res.matched_count > 0 {
                (StatusCode::OK, Json(ApiResponse { message: "Supplier updated".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Supplier not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("update_supplier error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Update failed: {}", e) 
            }))
        }
    }
}

async fn delete_supplier(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /suppliers/{}", id);
    
    let collection = state.db.collection::<Document>("suppliers");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => {
            println!("Parsed ObjectId successfully: {}", oid);
            oid
        },
        Err(e) => {
            eprintln!("Failed to parse ObjectId '{}': {:?}", id, e);
            return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
                message: format!("Invalid ID format: {}", e) 
            }));
        }
    };

    match collection.delete_one(doc! { "_id": oid }, None).await {
        Ok(res) => {
            println!("Delete result - deleted: {}", res.deleted_count);
            if res.deleted_count > 0 {
                (StatusCode::OK, Json(ApiResponse { message: "Supplier deleted".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Supplier not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("delete_supplier error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Delete failed: {}", e) 
            }))
        }
    }
}

async fn bulk_delete_suppliers(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("BULK DELETE SUPPLIERS - Received {} IDs", payload.ids.len());
    println!("IDs: {:?}", payload.ids);
    
    let collection = state.db.collection::<Document>("suppliers");
    
    let oids: Vec<ObjectId> = payload.ids
        .iter()
        .filter_map(|id| {
            match ObjectId::parse_str(id) {
                Ok(oid) => {
                    println!("Parsed ID: {} -> {:?}", id, oid);
                    Some(oid)
                }
                Err(e) => {
                    eprintln!("Failed to parse ID '{}': {:?}", id, e);
                    None
                }
            }
        })
        .collect();

    println!("Successfully parsed {} ObjectIds", oids.len());

    if oids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
            message: "No valid IDs provided".into() 
        }));
    }

    match collection.delete_many(doc! { "_id": { "$in": oids } }, None).await {
        Ok(res) => {
            println!("Bulk delete result - deleted: {}", res.deleted_count);
            (StatusCode::OK, Json(ApiResponse { 
                message: format!("{} suppliers deleted", res.deleted_count) 
            }))
        }
        Err(e) => {
            eprintln!("bulk_delete_suppliers error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Bulk delete failed: {}", e) 
            }))
        }
    }
}