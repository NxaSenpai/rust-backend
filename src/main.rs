use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post, patch, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use core::str;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use mongodb::{Client, bson::{doc, Document}};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use rand_core::OsRng;
use mongodb::options::IndexOptions;
use mongodb::IndexModel;
use std::collections::HashMap;
use axum::extract::{Query, Path, Multipart};
use futures::stream::TryStreamExt;
use mongodb::bson::oid::ObjectId;
use std::fs;
use std::path::Path as StdPath;
use tower_http::services::ServeDir;

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

    let upload_dir = "uploads";
    if !StdPath::new(upload_dir).exists() {
        println!("Creating uploads directory...");
        if let Err(e) = fs::create_dir_all(upload_dir) {
            eprintln!("Failed to create uploads directory: {:?}", e);
        } else {
            println!("Uploads directory created successfully");
        }
    } else {
        println!("Uploads directory already exists");
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/user", get(get_user))
        .route("/user", patch(update_user))
        .route("/user/:email", delete(delete_user_by_email))
        .route("/users/:id", delete(delete_user_by_id))
        .route("/users/bulk-delete", post(bulk_delete_users))
        .route("/users", get(get_users_by_role))
        .route("/products", get(get_products))
        .route("/products/:id", get(get_product_by_id))
        .route("/products", post(create_product))
        .route("/products/:id", patch(update_product))
        .route("/products/:id", delete(delete_product))
        .route("/products/bulk-delete", post(bulk_delete_products))
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
        .route("/promotions", get(get_promotions))
        .route("/promotions", post(create_promotion))
        .route("/promotions/:id", patch(update_promotion))
        .route("/promotions/:id", delete(delete_promotion))
        .route("/promotions/bulk-delete", post(bulk_delete_promotions))
        .route("/promotions/active", get(get_active_promotions))
        .route("/coupons", get(get_coupons))
        .route("/coupons", post(create_coupon))
        .route("/coupons/:id", patch(update_coupon))
        .route("/coupons/:id", delete(delete_coupon))
        .route("/coupons/validate", get(validate_coupon))
        .route("/coupons/bulk-delete", post(bulk_delete_coupons))
        .route("/upload", post(upload_image))
        .route("/wishlist", post(add_to_wishlist))
        .route("/wishlist", get(get_wishlist))
        .route("/orders", post(create_order))
        .route("/orders", get(get_orders))
        .route("/orders/all", get(get_all_orders))
        .route("/orders/:id/status", patch(update_order_status))
        .route("/orders/:id", delete(delete_order))
        .route("/wishlist/remove", post(remove_from_wishlist))
        .nest_service("/uploads", ServeDir::new("uploads"))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    println!("Uploads will be served from http://localhost:3000/uploads/");
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
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: Option<String>,
    email: Option<String>,
    role: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    message: Option<String>,
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<UserResponse>) {
    let email = match params.get("email") {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(UserResponse {
            id: None,
            name: None,
            email: None,
            role: None,
            created_at: None,
            message: Some("Email parameter required".into())
        }))
    };

    let users = state.db.collection::<Document>("users");
    match users.find_one(doc! { "email": &email }, None).await {
        Ok(Some(doc)) => {
            let id = doc.get_object_id("_id")
                .ok()
                .map(|oid| oid.to_hex());
            
            (StatusCode::OK, Json(UserResponse {
                id,
                name: doc.get_str("name").ok().map(String::from),
                email: doc.get_str("email").ok().map(String::from),
                role: doc.get_str("role").ok().map(String::from),
                created_at: doc.get_str("createdAt").ok().map(String::from),
                message: None
            }))
        },
        Ok(None) => (StatusCode::NOT_FOUND, Json(UserResponse {
            id: None,
            name: None,
            email: None,
            role: None,
            created_at: None,
            message: Some("User not found".into())
        })),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(UserResponse {
            id: None,
            name: None,
            email: None,
            role: None,
            created_at: None,
            message: Some("Database error".into())
        }))
    }
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateUserRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("UPDATE user: {}", payload.email);
    
    let users = state.db.collection::<Document>("users");
    
    let mut update_fields = doc! {};
    
    if let Some(name) = payload.name {
        if !name.trim().is_empty() {
            update_fields.insert("name", name);
        }
    }
    
    if let Some(password) = payload.password {
        if !password.is_empty() {
            let salt = SaltString::generate(&mut OsRng);
            let hashed = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .unwrap()
                .to_string();
            update_fields.insert("password", hashed);
        }
    }
    
    if update_fields.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
            message: "No fields to update".into() 
        }));
    }
    
    let update_doc = doc! { "$set": update_fields };
    
    match users.update_one(doc! { "email": &payload.email }, update_doc, None).await {
        Ok(res) => {
            if res.matched_count > 0 {
                println!("User updated successfully");
                (StatusCode::OK, Json(ApiResponse { message: "User updated".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "User not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("update_user error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Update failed: {}", e) 
            }))
        }
    }
}

async fn delete_user_by_email(
    State(state): State<Arc<AppState>>,
    Path(email): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /user/{}", email);
    
    let users = state.db.collection::<Document>("users");
    
    match users.delete_one(doc! { "email": &email }, None).await {
        Ok(res) => {
            if res.deleted_count > 0 {
                println!("User deleted successfully");
                (StatusCode::OK, Json(ApiResponse { message: "User deleted".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "User not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("delete_user error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Delete failed: {}", e) 
            }))
        }
    }
}

async fn delete_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /users/{}", id);
    
    let users = state.db.collection::<Document>("users");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(e) => {
            eprintln!("Failed to parse ObjectId '{}': {:?}", id, e);
            return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
                message: format!("Invalid ID format: {}", e) 
            }));
        }
    };
    
    match users.delete_one(doc! { "_id": oid }, None).await {
        Ok(res) => {
            if res.deleted_count > 0 {
                println!("User deleted successfully");
                (StatusCode::OK, Json(ApiResponse { message: "User deleted".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "User not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("delete_user error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Delete failed: {}", e) 
            }))
        }
    }
}

async fn bulk_delete_users(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("BULK DELETE USERS - Received {} IDs", payload.ids.len());
    println!("IDs: {:?}", payload.ids);
    
    let users = state.db.collection::<Document>("users");
    
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

    match users.delete_many(doc! { "_id": { "$in": oids } }, None).await {
        Ok(res) => {
            println!("Bulk delete result - deleted: {}", res.deleted_count);
            (StatusCode::OK, Json(ApiResponse { 
                message: format!("{} users deleted", res.deleted_count) 
            }))
        }
        Err(e) => {
            eprintln!("bulk_delete_users error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Bulk delete failed: {}", e) 
            }))
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

#[derive(Serialize)]
struct ProductResponse {
    #[serde(rename = "_id")]
    id: String,
    name: String,
    brand: String,
    category: String,
    supplier: String,
    #[serde(rename = "inStock")]
    in_stock: i32,
    price: f64,
    status: String,
    #[serde(rename = "imageSrc")]
    image_src: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "stockAt")]
    stock_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Product {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    name: String,
    brand: String,
    category: String,
    supplier: String,
    #[serde(rename = "inStock")]
    in_stock: i32,
    price: f64,
    status: String,
    #[serde(rename = "imageSrc")]
    image_src: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "stockAt", skip_serializing_if = "Option::is_none")]
    stock_at: Option<String>,
}

impl Product {
    fn to_response(self) -> ProductResponse {
        ProductResponse {
            id: self.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: self.name,
            brand: self.brand,
            category: self.category,
            supplier: self.supplier,
            in_stock: self.in_stock,
            price: self.price,
            status: self.status,
            image_src: self.image_src,
            description: self.description,
            stock_at: self.stock_at.unwrap_or_else(|| chrono::Utc::now().format("%a, %b %d, %Y").to_string()),
        }
    }
}

async fn update_category_product_count(
    db: &mongodb::Database,
    category_name: &str,
    increment: i32,
) -> Result<(), mongodb::error::Error> {
    let collection = db.collection::<Document>("categories");
    collection.update_one(
        doc! { "name": category_name },
        doc! { "$inc": { "productCount": increment } },
        None,
    ).await?;
    Ok(())
}

async fn update_supplier_product_count(
    db: &mongodb::Database,
    supplier_name: &str,
    increment: i32,
) -> Result<(), mongodb::error::Error> {
    let collection = db.collection::<Document>("suppliers");
    collection.update_one(
        doc! { "companyName": supplier_name },
        doc! { "$inc": { "productCount": increment } },
        None,
    ).await?;
    Ok(())
}

async fn create_product(
    State(state): State<Arc<AppState>>,
    Json(mut payload): Json<Product>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating product: {:?}", payload);
    
    let collection = state.db.collection::<Document>("products");
    
    if payload.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Product name is required".into()
        }));
    }
    
    if payload.price <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Price must be greater than 0".into()
        }));
    }
    
    if payload.image_src.is_empty() {
        payload.image_src = "/placeholder.png".to_string();
    }
    
    let now = chrono::Utc::now().to_rfc3339();
    
    let doc = doc! {
        "name": &payload.name,
        "brand": &payload.brand,
        "category": &payload.category,
        "supplier": &payload.supplier,
        "inStock": payload.in_stock,
        "price": payload.price,
        "status": &payload.status,
        "imageSrc": &payload.image_src,
        "description": payload.description.as_ref().unwrap_or(&String::new()),
        "stockAt": now
    };
    
    match collection.insert_one(doc, None).await {
        Ok(_) => {
            println!("Product created successfully");
            
            let _ = update_category_product_count(&state.db, &payload.category, 1).await;
            let _ = update_supplier_product_count(&state.db, &payload.supplier, 1).await;
            
            (StatusCode::CREATED, Json(ApiResponse {
                message: "Product created successfully".into()
            }))
        }
        Err(e) => {
            eprintln!("Failed to create product: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to create product".into()
            }))
        }
    }
}

async fn update_product(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<Product>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("UPDATE /products/{}", id);
    println!("Payload: {:?}", payload);
    
    let collection = state.db.collection::<Document>("products");
    
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

    let old_product = match collection.find_one(doc! { "_id": oid }, None).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Product not found".into() }));
        }
        Err(e) => {
            eprintln!("Error fetching old product: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: "Failed to fetch product".into() 
            }));
        }
    };

    let old_category = old_product.get_str("category").unwrap_or("").to_string();
    let old_supplier = old_product.get_str("supplier").unwrap_or("").to_string();
    
    let new_category = payload.category.clone();
    let new_supplier = payload.supplier.clone();

    let update_doc = doc! {
        "$set": {
            "name": payload.name,
            "brand": payload.brand,
            "category": &new_category,
            "supplier": &new_supplier,
            "inStock": payload.in_stock,
            "price": payload.price,
            "status": payload.status,
            "imageSrc": payload.image_src,
            "description": payload.description.unwrap_or_default(),
        }
    };

    match collection.update_one(doc! { "_id": oid }, update_doc, None).await {
        Ok(res) => {
            println!("Update result - matched: {}, modified: {}", res.matched_count, res.modified_count);
            
            if res.matched_count > 0 {
                if old_category != new_category {
                    if let Err(e) = update_category_product_count(&state.db, &old_category, -1).await {
                        eprintln!("Failed to decrement old category count: {:?}", e);
                    }
                    if let Err(e) = update_category_product_count(&state.db, &new_category, 1).await {
                        eprintln!("Failed to increment new category count: {:?}", e);
                    }
                }
                
                if old_supplier != new_supplier {
                    if let Err(e) = update_supplier_product_count(&state.db, &old_supplier, -1).await {
                        eprintln!("Failed to decrement old supplier count: {:?}", e);
                    }
                    if let Err(e) = update_supplier_product_count(&state.db, &new_supplier, 1).await {
                        eprintln!("Failed to increment new supplier count: {:?}", e);
                    }
                }
                
                (StatusCode::OK, Json(ApiResponse { message: "Product updated".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Product not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("update_product error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Update failed: {}", e) 
            }))
        }
    }
}

async fn delete_product(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /products/{}", id);
    
    let collection = state.db.collection::<Document>("products");
    
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

    let product = match collection.find_one(doc! { "_id": oid }, None).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Product not found".into() }));
        }
        Err(e) => {
            eprintln!("Error fetching product: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: "Failed to fetch product".into() 
            }));
        }
    };

    let category = product.get_str("category").unwrap_or("").to_string();
    let supplier = product.get_str("supplier").unwrap_or("").to_string();

    match collection.delete_one(doc! { "_id": oid }, None).await {
        Ok(res) => {
            println!("Delete result - deleted: {}", res.deleted_count);
            if res.deleted_count > 0 {
                if let Err(e) = update_category_product_count(&state.db, &category, -1).await {
                    eprintln!("Failed to decrement category count: {:?}", e);
                }
                if let Err(e) = update_supplier_product_count(&state.db, &supplier, -1).await {
                    eprintln!("Failed to decrement supplier count: {:?}", e);
                }
                
                (StatusCode::OK, Json(ApiResponse { message: "Product deleted".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Product not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("delete_product error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Delete failed: {}", e) 
            }))
        }
    }
}

async fn bulk_delete_products(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("BULK DELETE PRODUCTS - Received {} IDs", payload.ids.len());
    println!("IDs: {:?}", payload.ids);
    
    let collection = state.db.collection::<Document>("products");
    
    let oids: Vec<ObjectId> = payload.ids
        .iter()
        .filter_map(|id| ObjectId::parse_str(id).ok())
        .collect();

    println!("Successfully parsed {} ObjectIds", oids.len());

    if oids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse { 
            message: "No valid IDs provided".into() 
        }));
    }

    let products_cursor = collection.find(doc! { "_id": { "$in": &oids } }, None).await;
    
    if let Ok(cursor) = products_cursor {
        let products: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
        
        let mut category_counts: HashMap<String, i32> = HashMap::new();
        let mut supplier_counts: HashMap<String, i32> = HashMap::new();
        
        for product in products {
            if let Ok(category) = product.get_str("category") {
                *category_counts.entry(category.to_string()).or_insert(0) += 1;
            }
            if let Ok(supplier) = product.get_str("supplier") {
                *supplier_counts.entry(supplier.to_string()).or_insert(0) += 1;
            }
        }

        match collection.delete_many(doc! { "_id": { "$in": oids } }, None).await {
            Ok(res) => {
                println!("Bulk delete result - deleted: {}", res.deleted_count);
                
                for (category, count) in category_counts {
                    if let Err(e) = update_category_product_count(&state.db, &category, -count).await {
                        eprintln!("Failed to update category {} count: {:?}", category, e);
                    }
                }
                
                for (supplier, count) in supplier_counts {
                    if let Err(e) = update_supplier_product_count(&state.db, &supplier, -count).await {
                        eprintln!("Failed to update supplier {} count: {:?}", supplier, e);
                    }
                }
                
                (StatusCode::OK, Json(ApiResponse { 
                    message: format!("{} products deleted", res.deleted_count) 
                }))
            }
            Err(e) => {
                eprintln!("bulk_delete_products error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                    message: format!("Bulk delete failed: {}", e) 
                }))
            }
        }
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
            message: "Failed to fetch products".into() 
        }))
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

#[derive(Serialize, Deserialize, Debug)]
struct Promotion {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    #[serde(rename = "productId")]
    product_id: String,
    #[serde(rename = "productName")]
    product_name: String,
    #[serde(rename = "originalPrice")]
    original_price: f64,
    discount: f64,
    #[serde(rename = "discountPercentage")]
    discount_percentage: f64,
    #[serde(rename = "salePrice")]
    sale_price: f64,
    #[serde(rename = "startDate")]
    start_date: Option<String>,
    #[serde(rename = "endDate")]
    end_date: Option<String>,
    status: String,
}

#[derive(Serialize)]
struct PromotionResponse {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "productId")]
    product_id: String,
    #[serde(rename = "productName")]
    product_name: String,
    #[serde(rename = "originalPrice")]
    original_price: f64,
    discount: f64,
    #[serde(rename = "discountPercentage")]
    discount_percentage: f64,
    #[serde(rename = "salePrice")]
    sale_price: f64,
    #[serde(rename = "startDate")]
    start_date: String,
    #[serde(rename = "endDate")]
    end_date: String,
    status: String,
}

impl Promotion {
    fn to_response(self) -> PromotionResponse {
        PromotionResponse {
            id: self.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            product_id: self.product_id,
            product_name: self.product_name,
            original_price: self.original_price,
            discount: self.discount,
            discount_percentage: self.discount,
            sale_price: self.sale_price,
            start_date: self.start_date.unwrap_or_default(),
            end_date: self.end_date.unwrap_or_default(),
            status: self.status,
        }
    }
}

async fn get_promotions(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<PromotionResponse>>) {
    println!("GET /promotions called");
    let collection = state.db.collection::<Promotion>("promotions");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            match cursor.try_collect::<Vec<Promotion>>().await {
                Ok(promotions) => {
                    let responses: Vec<PromotionResponse> = promotions
                        .into_iter()
                        .map(|p| p.to_response())
                        .collect();
                    
                    println!("Returning {} promotions", responses.len());
                    (StatusCode::OK, Json(responses))
                }
                Err(e) => {
                    eprintln!("Error collecting promotions: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
                }
            }
        }
        Err(e) => {
            eprintln!("Error querying promotions: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn update_promotion(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<UpdatePromotionRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("UPDATE promotion: {}", id);
    
    let promotions = state.db.collection::<Document>("promotions");
    let products = state.db.collection::<Document>("products");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid promotion ID format".into()
            }));
        }
    };
    
    let product_oid = match ObjectId::parse_str(&payload.product_id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid product ID format".into()
            }));
        }
    };
    
    let product = match products.find_one(doc! { "_id": product_oid }, None).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(ApiResponse {
                message: "Product not found".into()
            }));
        }
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to fetch product".into()
            }));
        }
    };
    
    let product_name = product.get_str("name").unwrap_or("Unknown").to_string();
    let original_price = product.get_f64("price").unwrap_or(0.0);
    let sale_price = original_price - (original_price * payload.discount / 100.0);
    
    let update_doc = doc! {
        "$set": {
            "productId": &payload.product_id,
            "productName": product_name,
            "originalPrice": original_price,
            "discount": payload.discount,
            "discountPercentage": payload.discount,
            "salePrice": sale_price,
            "startDate": &payload.start_date,
            "endDate": &payload.end_date,
            "status": &payload.status
        }
    };
    
    match promotions.update_one(doc! { "_id": oid }, update_doc, None).await {
        Ok(result) => {
            if result.matched_count > 0 {
                (StatusCode::OK, Json(ApiResponse {
                    message: "Promotion updated successfully".into()
                }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Promotion not found".into()
                }))
            }
        }
        Err(e) => {
            eprintln!("Update error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to update promotion".into()
            }))
        }
    }
}

#[derive(Deserialize, Debug)]
struct UpdatePromotionRequest {
    #[serde(rename = "productId")]
    product_id: String,
    discount: f64,
    #[serde(rename = "startDate")]
    start_date: String,
    #[serde(rename = "endDate")]
    end_date: String,
    status: String,
}

async fn create_promotion(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdatePromotionRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating promotion: {:?}", payload);
    let collection = state.db.collection::<Document>("promotions");
    let products = state.db.collection::<Document>("products");

    let product_oid = match ObjectId::parse_str(&payload.product_id) {
        Ok(oid) => oid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid product ID".into()
            }));
        }
    };

    let product = match products.find_one(doc! { "_id": product_oid }, None).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(ApiResponse {
                message: "Product not found".into()
            }));
        }
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Database error".into()
            }));
        }
    };

    let product_name = product.get_str("name").unwrap_or("Unknown").to_string();
    let original_price = product.get_f64("price").unwrap_or(0.0);
    
    let discount = payload.discount;
    let sale_price = original_price - (original_price * discount / 100.0);

    let now = chrono::Utc::now().to_rfc3339();
    
    let doc = doc! {
        "productId": &payload.product_id,
        "productName": product_name,
        "originalPrice": original_price,
        "discount": discount,
        "discountPercentage": discount,
        "salePrice": sale_price,
        "startDate": &payload.start_date,
        "endDate": &payload.end_date,
        "status": &payload.status,
        "createdAt": now
    };

    match collection.insert_one(doc, None).await {
        Ok(_) => {
            println!("Promotion created successfully");
            (StatusCode::CREATED, Json(ApiResponse {
                message: "Promotion created successfully".into()
            }))
        }
        Err(e) => {
            eprintln!("Failed to create promotion: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to create promotion".into()
            }))
        }
    }
}

async fn delete_promotion(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE promotion: {}", id);
    let collection = state.db.collection::<Document>("promotions");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Invalid promotion ID".into()
        }))
    };

    match collection.delete_one(doc! { "_id": oid }, None).await {
        Ok(result) => {
            if result.deleted_count == 0 {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Promotion not found".into()
                }))
            } else {
                (StatusCode::OK, Json(ApiResponse {
                    message: "Promotion deleted".into()
                }))
            }
        }
        Err(e) => {
            eprintln!("Delete error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Delete failed".into()
            }))
        }
    }
}

async fn bulk_delete_promotions(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Bulk delete promotions: {:?}", payload.ids);
    let collection = state.db.collection::<Document>("promotions");
    
    let object_ids: Vec<ObjectId> = payload.ids.iter()
        .filter_map(|id| ObjectId::parse_str(id).ok())
        .collect();
    
    if object_ids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "No valid IDs provided".into()
        }));
    }

    match collection.delete_many(doc! { "_id": { "$in": object_ids } }, None).await {
        Ok(result) => (StatusCode::OK, Json(ApiResponse {
            message: format!("Deleted {} promotions", result.deleted_count)
        })),
        Err(e) => {
            eprintln!("Bulk delete error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Bulk delete failed".into()
            }))
        }
    }
}

async fn get_users_by_role(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Vec<UserResponse>>) {
    let role = params.get("role").map(|s| s.as_str()).unwrap_or("user");
    
    let users = state.db.collection::<Document>("users");
    
    let filter = match role {
        "all" => doc! {},
        _ => doc! { "role": role },
    };
    
    match users.find(filter, None).await {
        Ok(cursor) => {
            let mut user_list = Vec::new();
            let users_vec: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
            
            for user_doc in users_vec {
                let id = user_doc.get_object_id("_id")
                    .ok()
                    .map(|oid| oid.to_hex());
                
                user_list.push(UserResponse {
                    id,
                    name: user_doc.get_str("name").ok().map(|s| s.to_string()),
                    email: user_doc.get_str("email").ok().map(|s| s.to_string()),
                    role: user_doc.get_str("role").ok().map(|s| s.to_string()),
                    created_at: user_doc.get_str("createdAt").ok().map(|s| s.to_string()),
                    message: None,
                });
            }
            
            (StatusCode::OK, Json(user_list))
        }
        Err(e) => {
            eprintln!("get_users_by_role error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn get_products(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<ProductResponse>>) {
    println!("GET /products called");
    let collection = state.db.collection::<Product>("products");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            let products: Vec<Product> = cursor.try_collect().await.unwrap_or_default();
            let response: Vec<ProductResponse> = products
                .into_iter()
                .map(|prod| prod.to_response())
                .collect();
            println!("Found {} products", response.len());
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            eprintln!("get_products error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

#[derive(Serialize)]
struct UploadResponse {
    url: String,
    filename: String,
}

async fn upload_image(
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), StatusCode> {
    println!("=== Upload image endpoint called ===");
    
    let upload_dir = "uploads";
    
    if let Err(e) = fs::create_dir_all(upload_dir) {
        eprintln!("Failed to create upload directory: {:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        println!("Field name: {}", name);
        
        if name != "image" {
            println!("Skipping non-image field");
            continue;
        }
        
        let filename = match field.file_name() {
            Some(f) => f.to_string(),
            None => {
                eprintln!("No filename provided");
                return Err(StatusCode::BAD_REQUEST);
            }
        };
        
        println!("Received file: {}", filename);
        
        let ext = StdPath::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("jpg")
            .to_lowercase();
        
        if !["jpg", "jpeg", "png", "gif", "webp"].contains(&ext.as_str()) {
            eprintln!("Invalid file type: {}", ext);
            return Err(StatusCode::BAD_REQUEST);
        }
        
        let data = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Failed to read file data: {:?}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        println!("File size: {} bytes", data.len());
        
        if data.len() > 10 * 1024 * 1024 {
            eprintln!("File too large: {} bytes", data.len());
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        
        let timestamp = chrono::Utc::now().timestamp();
        let uuid = uuid::Uuid::new_v4();
        let new_filename = format!("{}_{}.{}", timestamp, uuid, ext);
        let filepath = format!("{}/{}", upload_dir, new_filename);
        
        println!("Saving to: {}", filepath);
        
        if let Err(e) = fs::write(&filepath, &data) {
            eprintln!("Failed to save file: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        
        println!("File saved successfully: {}", filepath);
        
        let url = format!("/uploads/{}", new_filename);
        
        println!("Returning URL: {}", url);
        
        return Ok((
            StatusCode::OK,
            Json(UploadResponse {
                url,
                filename: new_filename,
            })
        ));
    }
    
    eprintln!("No image field found in request");
    Err(StatusCode::BAD_REQUEST)
}

async fn get_active_promotions(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<PromotionWithProduct>>) {
    let promotions = state.db.collection::<Document>("promotions");
    let products = state.db.collection::<Document>("products");
    
    let now = chrono::Utc::now().to_rfc3339();
    
    let cursor = promotions
        .find(
            doc! {
                "status": "Active",
                "endDate": { "$gte": now }
            },
            None,
        )
        .await;

    let Ok(mut cursor) = cursor else {
        eprintln!("Failed to query promotions");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]));
    };

    let mut result = Vec::new();

    while let Ok(Some(doc)) = cursor.try_next().await {
        let promo_id = doc.get_object_id("_id").ok().map(|id| id.to_hex());
        let product_id = doc.get_str("productId").ok();
        let discount = doc.get_f64("discountPercentage").unwrap_or(
            doc.get_f64("discount").unwrap_or(0.0)
        );
        let start_date = doc.get_str("startDate").ok().map(String::from);
        let end_date = doc.get_str("endDate").ok().map(String::from);
        
        if let Some(pid) = product_id {
            let oid = match ObjectId::parse_str(pid) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("Failed to parse product ID '{}': {:?}", pid, e);
                    continue;
                }
            };
            
            match products.find_one(doc! { "_id": oid }, None).await {
                Ok(Some(product_doc)) => {
                    let original_price = product_doc.get_f64("price").unwrap_or(0.0);
                    let sale_price = original_price - (original_price * discount / 100.0);
                    
                    result.push(PromotionWithProduct {
                        id: promo_id.unwrap_or_default(),
                        product_id: pid.to_string(),
                        product_name: product_doc.get_str("name").unwrap_or("Unknown Product").to_string(),
                        product_image: product_doc.get_str("imageSrc").unwrap_or("/placeholder.png").to_string(),
                        original_price,
                        discount,
                        sale_price,
                        start_date: start_date.unwrap_or_default(),
                        end_date: end_date.unwrap_or_default(),
                    });
                }
                Ok(None) => {
                    eprintln!("Product not found for ID: {}", pid);
                }
                Err(e) => {
                    eprintln!("Failed to fetch product {}: {:?}", pid, e);
                }
            }
        }
    }

    println!("Found {} active promotions", result.len());
    (StatusCode::OK, Json(result))
}

#[derive(Serialize)]
struct PromotionWithProduct {
    id: String,
    product_id: String,
    product_name: String,
    product_image: String,
    original_price: f64,
    discount: f64,
    sale_price: f64,
    start_date: String,
    end_date: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Coupon {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    code: String,
    #[serde(rename = "type")]
    coupon_type: String,
    value: f64,
    #[serde(rename = "expiryDate")]
    expiry_date: String,
    #[serde(rename = "maxUses", skip_serializing_if = "Option::is_none")]
    max_uses: Option<i32>,
    #[serde(rename = "currentUses")]
    current_uses: i32,
    #[serde(rename = "minPurchase", skip_serializing_if = "Option::is_none")]
    min_purchase: Option<f64>,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Serialize)]
struct CouponResponse {
    #[serde(rename = "_id")]
    id: String,
    code: String,
    #[serde(rename = "type")]
    coupon_type: String,
    value: f64,
    #[serde(rename = "expiryDate")]
    expiry_date: String,
    #[serde(rename = "maxUses", skip_serializing_if = "Option::is_none")]
    max_uses: Option<i32>,
    #[serde(rename = "currentUses")]
    current_uses: i32,
    #[serde(rename = "minPurchase", skip_serializing_if = "Option::is_none")]
    min_purchase: Option<f64>,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

impl Coupon {
    fn to_response(self) -> CouponResponse {
        CouponResponse {
            id: self.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            code: self.code,
            coupon_type: self.coupon_type,
            value: self.value,
            expiry_date: self.expiry_date,
            max_uses: self.max_uses,
            current_uses: self.current_uses,
            min_purchase: self.min_purchase,
            active: self.active,
            notes: self.notes,
            created_at: self.created_at,
        }
    }
}

#[derive(Deserialize, Debug)]
struct CreateCouponRequest {
    code: String,
    #[serde(rename = "type")]
    coupon_type: String,
    value: f64,
    #[serde(rename = "expiryDate")]
    expiry_date: String,
    #[serde(rename = "maxUses")]
    max_uses: Option<i32>,
    #[serde(rename = "minPurchase")]
    min_purchase: Option<f64>,
    active: bool,
    notes: Option<String>,
}

#[derive(Deserialize, Debug)]
struct UpdateCouponRequest {
    #[serde(rename = "_id")]
    id: String,
    code: String,
    #[serde(rename = "type")]
    coupon_type: String,
    value: f64,
    #[serde(rename = "expiryDate")]
    expiry_date: String,
    #[serde(rename = "maxUses")]
    max_uses: Option<i32>,
    #[serde(rename = "minPurchase")]
    min_purchase: Option<f64>,
    active: bool,
    notes: Option<String>,
}


async fn get_coupons(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<CouponResponse>>) {
    println!("GET /coupons called");
    let collection = state.db.collection::<Coupon>("coupons");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            match cursor.try_collect::<Vec<Coupon>>().await {
                Ok(coupons) => {
                    let responses: Vec<CouponResponse> = coupons
                        .into_iter()
                        .map(|c| c.to_response())
                        .collect();
                    
                    println!("Returning {} coupons", responses.len());
                    (StatusCode::OK, Json(responses))
                }
                Err(e) => {
                    eprintln!("Error collecting coupons: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
                }
            }
        }
        Err(e) => {
            eprintln!("Error querying coupons: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn create_coupon(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateCouponRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating coupon: {:?}", payload);
    
    if payload.code.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Coupon code cannot be empty".into()
        }));
    }
    
    if payload.value <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Coupon value must be greater than 0".into()
        }));
    }
    
    if payload.coupon_type == "percentage" && payload.value > 100.0 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Percentage discount cannot exceed 100%".into()
        }));
    }
    
    let collection = state.db.collection::<Document>("coupons");
    
    let code_upper = payload.code.to_uppercase();
    match collection.find_one(doc! { "code": &code_upper }, None).await {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, Json(ApiResponse {
                message: "Coupon code already exists".into()
            }));
        }
        Ok(None) => {},
        Err(e) => {
            eprintln!("Database error checking coupon: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Database error".into()
            }));
        }
    }
    
    let now = chrono::Utc::now().to_rfc3339();
    
    let doc = doc! {
        "code": code_upper,
        "type": payload.coupon_type,
        "value": payload.value,
        "expiryDate": payload.expiry_date,
        "maxUses": payload.max_uses,
        "currentUses": 0,
        "minPurchase": payload.min_purchase,
        "active": payload.active,
        "notes": payload.notes,
        "createdAt": now
    };
    
    match collection.insert_one(doc, None).await {
        Ok(_) => {
            println!("Coupon created successfully");
            (StatusCode::CREATED, Json(ApiResponse {
                message: "Coupon created successfully".into()
            }))
        }
        Err(e) => {
            eprintln!("Failed to create coupon: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to create coupon".into()
            }))
        }
    }
}

async fn update_coupon(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateCouponRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Updating coupon: {:?}", payload);
    
    if payload.code.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Coupon code cannot be empty".into()
        }));
    }
    
    if payload.value <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Coupon value must be greater than 0".into()
        }));
    }
    
    if payload.coupon_type == "percentage" && payload.value > 100.0 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Percentage discount cannot exceed 100%".into()
        }));
    }
    
    let collection = state.db.collection::<Document>("coupons");
    
    let oid = match ObjectId::parse_str(&payload.id) {
        Ok(oid) => oid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid coupon ID".into()
            }));
        }
    };
    
    let code_upper = payload.code.to_uppercase();
    match collection.find_one(doc! { 
        "code": &code_upper,
        "_id": { "$ne": &oid }
    }, None).await {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, Json(ApiResponse {
                message: "Coupon code already exists".into()
            }));
        }
        Ok(None) => {},
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Database error".into()
            }));
        }
    }
    
    let update_doc = doc! {
        "$set": {
            "code": code_upper,
            "type": payload.coupon_type,
            "value": payload.value,
            "expiryDate": payload.expiry_date,
            "maxUses": payload.max_uses,
            "minPurchase": payload.min_purchase,
            "active": payload.active,
            "notes": payload.notes,
        }
    };
    
    println!("Update document: {:?}", update_doc);
    
    match collection.update_one(doc! { "_id": oid }, update_doc, None).await {
        Ok(result) => {
            if result.matched_count > 0 {
                println!("Coupon updated successfully");
                (StatusCode::OK, Json(ApiResponse {
                    message: "Coupon updated successfully".into()
                }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Coupon not found".into()
                }))

            }
        }
        Err(e) => {
            eprintln!("Failed to update coupon: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to update coupon".into()
            }))
        }
    }
}

async fn delete_coupon(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("DELETE /coupons/{}", id);
    let collection = state.db.collection::<Document>("coupons");
    
    let oid = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid coupon ID".into()
            }));
        }
    };
    
    match collection.delete_one(doc! { "_id": oid }, None).await {
        Ok(result) => {
            if result.deleted_count > 0 {
                (StatusCode::OK, Json(ApiResponse {
                    message: "Coupon deleted successfully".into()
                }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Coupon not found".into()
                }))
            }
        }
        Err(e) => {
            eprintln!("Failed to delete coupon: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to delete coupon".into()
            }))
        }
    }
}

async fn bulk_delete_coupons(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BulkDeleteRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("BULK DELETE COUPONS - Received {} IDs", payload.ids.len());
    
    let collection = state.db.collection::<Document>("coupons");
    
    let oids: Vec<ObjectId> = payload.ids
        .iter()
        .filter_map(|id| ObjectId::parse_str(id).ok())
        .collect();
    
    if oids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "No valid IDs provided".into()
        }));
    }
    
    match collection.delete_many(doc! { "_id": { "$in": oids } }, None).await {
        Ok(result) => {
            (StatusCode::OK, Json(ApiResponse {
                message: format!("Deleted {} coupons", result.deleted_count)
            }))
        }
        Err(e) => {
            eprintln!("Failed to bulk delete: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to delete coupons".into()
            }))
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct WishlistItem {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "productId")]
    product_id: String,
    #[serde(rename = "addedAt", skip_serializing_if = "Option::is_none")]
    added_at: Option<String>,
}

async fn add_to_wishlist(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WishlistItem>,
) -> (StatusCode, Json<ApiResponse>) {
    let collection = state.db.collection::<Document>("wishlist");
    let now = chrono::Utc::now().to_rfc3339();

    if let Ok(Some(_)) = collection.find_one(doc! {
        "userId": &payload.user_id,
        "productId": &payload.product_id
    }, None).await {
        return (StatusCode::CONFLICT, Json(ApiResponse { message: "Already in wishlist".into() }));
    }

    let doc = doc! {
        "userId": &payload.user_id,
        "productId": &payload.product_id,
        "addedAt": now
    };

    match collection.insert_one(doc, None).await {
        Ok(_) => (StatusCode::CREATED, Json(ApiResponse { message: "Added to wishlist".into() })),
        Err(e) => {
            eprintln!("Wishlist insert error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { message: "Failed to add".into() }))
        }
    }
}

async fn get_wishlist(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Vec<WishlistItem>>) {
    let user_id = match params.get("userId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, Json(vec![])),
    };

    let collection = state.db.collection::<WishlistItem>("wishlist");
    match collection.find(doc! { "userId": user_id }, None).await {
        Ok(cursor) => {
            let items: Vec<WishlistItem> = cursor.try_collect().await.unwrap_or_default();
            (StatusCode::OK, Json(items))
        }
        Err(e) => {
            eprintln!("Wishlist fetch error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

async fn remove_from_wishlist(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WishlistItem>,
) -> (StatusCode, Json<ApiResponse>) {
    let collection = state.db.collection::<Document>("wishlist");
    match collection.delete_one(doc! {
        "userId": &payload.user_id,
        "productId": &payload.product_id
    }, None).await {
        Ok(res) => {
            if res.deleted_count > 0 {
                (StatusCode::OK, Json(ApiResponse { message: "Removed from wishlist".into() }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse { message: "Not found".into() }))
            }
        }
        Err(e) => {
            eprintln!("Wishlist delete error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { message: "Failed to remove".into() }))
        }
    }
}

async fn get_product_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Option<Product>>) {
    let collection = state.db.collection::<Product>("products");
    
    let object_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(None)),
    };
    
    match collection.find_one(doc! { "_id": object_id }, None).await {
        Ok(Some(product)) => (StatusCode::OK, Json(Some(product))),
        Ok(None) => (StatusCode::NOT_FOUND, Json(None)),
        Err(e) => {
            eprintln!("Error fetching product: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}

async fn validate_coupon(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let code = match params.get("code") {
        Some(c) => c.to_uppercase(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "message": "Coupon code required"
        }))),
    };
    
    let collection = state.db.collection::<Document>("coupons");
    
    match collection.find_one(doc! { "code": &code }, None).await {
        Ok(Some(coupon_doc)) => {
            let active = coupon_doc.get_bool("active").unwrap_or(false);
            if !active {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "message": "Coupon is not active"
                })));
            }
            
            if let Ok(expiry) = coupon_doc.get_str("expiryDate") {
                if let Ok(expiry_date) = chrono::DateTime::parse_from_rfc3339(expiry) {
                    if expiry_date < chrono::Utc::now() {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                            "message": "Coupon has expired"
                        })));
                    }
                }
            }
            
            if let Some(max_uses) = coupon_doc.get_i32("maxUses").ok() {
                let current_uses = coupon_doc.get_i32("currentUses").unwrap_or(0);
                if current_uses >= max_uses {
                    return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                        "message": "Coupon usage limit reached"
                    })));
                }
            }
            
            (StatusCode::OK, Json(serde_json::json!({
                "code": code,
                "type": coupon_doc.get_str("type").unwrap_or("fixed"),
                "value": coupon_doc.get_f64("value").unwrap_or(0.0),
                "minPurchase": coupon_doc.get_f64("minPurchase").ok(),
            })))
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "message": "Invalid coupon code"
        }))),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "message": "Server error"
            })))
        }
    }
}


#[derive(Deserialize, Serialize, Debug, Clone)]
struct OrderItem {
    #[serde(rename = "productId")]
    product_id: String,
    name: String,
    image: String,
    price: f64,
    quantity: i32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct DeliveryInfo {
    address: String,
    city: String,
    #[serde(rename = "postalCode", skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct CouponInfo {
    code: String,
    #[serde(rename = "type")]
    coupon_type: String,
    value: f64,
    #[serde(rename = "discountAmount")]
    discount_amount: f64,
}

#[derive(Deserialize, Debug)]
struct CreateOrderRequest {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "userEmail")]
    user_email: String,
    username: String,
    items: Vec<OrderItem>,
    payment: String,
    delivery: DeliveryInfo,
    coupon: Option<CouponInfo>,
    #[serde(rename = "calculatedSubtotal")]
    calculated_subtotal: f64,
    #[serde(rename = "calculatedTax")]
    calculated_tax: f64,
    #[serde(rename = "calculatedDeliveryFee")]
    calculated_delivery_fee: f64,
    #[serde(rename = "calculatedTotal")]
    calculated_total: f64,
}

async fn create_order(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateOrderRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Creating order for user: {}", payload.user_email);
    
    if payload.items.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            message: "Order must contain at least one item".into()
        }));
    }
    
    let orders_collection = state.db.collection::<Document>("orders");
    let products_collection = state.db.collection::<Document>("products");
    
    for item in &payload.items {
        let product_result = products_collection
            .find_one(doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&item.product_id).ok() }, None)
            .await;
        
        match product_result {
            Ok(Some(product)) => {
                let current_stock = product.get_i32("inStock").unwrap_or(0);
                if current_stock < item.quantity {
                    return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                        message: format!("Insufficient stock for {}. Available: {}, Requested: {}", 
                            item.name, current_stock, item.quantity)
                    }));
                }
            }
            Ok(None) => {
                return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                    message: format!("Product {} not found", item.name)
                }));
            }
            Err(e) => {
                eprintln!("Error checking product stock: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    message: "Failed to verify product availability".into()
                }));
            }
        }
    }
    
    let subtotal = payload.calculated_subtotal;
    let tax = payload.calculated_tax;
    let delivery_fee = payload.calculated_delivery_fee;
    let total = payload.calculated_total;
    
    let timestamp = chrono::Utc::now().timestamp();
    let order_number = format!("ORD{}", timestamp);
    let now = chrono::Utc::now().to_rfc3339();
    
    let items_docs: Vec<Document> = payload.items.iter().map(|item| {
        doc! {
            "productId": &item.product_id,
            "name": &item.name,
            "image": &item.image,
            "price": item.price,
            "quantity": item.quantity,
        }
    }).collect();
    
    let mut order_doc = doc! {
        "userId": &payload.user_id,
        "userEmail": &payload.user_email,
        "userName": &payload.username,
        "items": items_docs,
        "subtotal": subtotal,
        "tax": tax,
        "deliveryFee": delivery_fee,
        "total": total,
        "status": "processing",
        "payment": &payload.payment,
        "delivery": {
            "address": &payload.delivery.address,
            "city": &payload.delivery.city,
            "postalCode": payload.delivery.postal_code,
            "phone": payload.delivery.phone,
        },
        "createdAt": &now,
        "orderNumber": &order_number,
    };
    
    if let Some(coupon) = &payload.coupon {
        order_doc.insert("coupon", doc! {
            "code": &coupon.code,
            "type": &coupon.coupon_type,
            "value": coupon.value,
            "discountAmount": coupon.discount_amount,
        });
    }
    
    match orders_collection.insert_one(order_doc, None).await {
        Ok(_) => {
            println!("Order created successfully: {}", order_number);
            
            for item in &payload.items {
                if let Ok(product_id) = mongodb::bson::oid::ObjectId::parse_str(&item.product_id) {
                    let update_result = products_collection.update_one(
                        doc! { "_id": product_id },
                        doc! { "$inc": { "inStock": -item.quantity } },
                        None
                    ).await;
                    
                    match update_result {
                        Ok(_) => {
                            println!("Updated stock for product {}: -{}", item.name, item.quantity);
                        }
                        Err(e) => {
                            eprintln!("Failed to update stock for {}: {:?}", item.name, e);
                        }
                    }
                }
            }
            
            (StatusCode::CREATED, Json(ApiResponse {
                message: format!("Order {} created successfully. Stock updated.", order_number)
            }))
        }
        Err(e) => {
            eprintln!("Failed to create order: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to create order".into()
            }))
        }
    }
}

async fn get_orders(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Vec<serde_json::Value>>) {
    let user_email = match params.get("userEmail") {
        Some(email) => email,
        None => {
            eprintln!("Missing userEmail parameter");
            return (StatusCode::BAD_REQUEST, Json(vec![]));
        }
    };
    
    println!("Fetching orders for user: {}", user_email);
    
    let collection = state.db.collection::<Document>("orders");
    
    match collection.find(doc! { "userEmail": user_email }, None).await {
        Ok(cursor) => {
            let orders: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
            
            let result: Vec<serde_json::Value> = orders.iter().map(|order| {
                let coupon_data = order.get_document("coupon").ok().map(|doc| {
                    serde_json::json!({
                        "code": doc.get_str("code").unwrap_or(""),
                        "type": doc.get_str("type").unwrap_or(""),
                        "value": doc.get_f64("value").unwrap_or(0.0),
                        "discountAmount": doc.get_f64("discountAmount").unwrap_or(0.0)
                    })
                });
                
                serde_json::json!({
                    "_id": order.get_object_id("_id").ok().map(|id| id.to_hex()),
                    "orderNumber": order.get_str("orderNumber").unwrap_or("N/A"),
                    "userId": order.get_str("userId").unwrap_or(""),
                    "userEmail": order.get_str("userEmail").unwrap_or(""),
                    "userName": order.get_str("userName").unwrap_or(""),
                    "items": order.get_array("items").ok().map(|items| {
                        items.iter().filter_map(|item| {
                            item.as_document().map(|doc| {
                                serde_json::json!({
                                    "productId": doc.get_str("productId").unwrap_or(""),
                                    "name": doc.get_str("name").unwrap_or(""),
                                    "image": doc.get_str("image").unwrap_or(""),
                                    "price": doc.get_f64("price").unwrap_or(0.0),
                                    "quantity": doc.get_i32("quantity").unwrap_or(0)
                                })
                            })
                        }).collect::<Vec<_>>()
                    }).unwrap_or_default(),
                    "subtotal": order.get_f64("subtotal").unwrap_or(0.0),
                    "tax": order.get_f64("tax").unwrap_or(0.0),
                    "deliveryFee": order.get_f64("deliveryFee").unwrap_or(0.0),
                    "total": order.get_f64("total").unwrap_or(0.0),
                    "status": order.get_str("status").unwrap_or("pending"),
                    "payment": order.get_str("payment").unwrap_or(""),
                    "delivery": order.get_document("delivery").ok().map(|doc| {
                        serde_json::json!({
                            "address": doc.get_str("address").unwrap_or(""),
                            "city": doc.get_str("city").unwrap_or(""),
                            "postalCode": doc.get_str("postalCode").ok(),
                            "phone": doc.get_str("phone").ok()
                        })
                    }).unwrap_or(serde_json::json!({})),
                    "coupon": coupon_data,
                    "createdAt": order.get_str("createdAt").unwrap_or(""),
                    "date": order.get_str("createdAt").unwrap_or("")
                })
            }).collect();
            
            println!("Found {} orders for user {}", result.len(), user_email);
            (StatusCode::OK, Json(result))
        }
        Err(e) => {
            eprintln!("Failed to fetch orders: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}


async fn get_all_orders(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<serde_json::Value>>) {
    println!("Fetching all orders for admin");
    
    let collection = state.db.collection::<Document>("orders");
    
    match collection.find(None, None).await {
        Ok(cursor) => {
            let orders: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
            
            let result: Vec<serde_json::Value> = orders.iter().map(|order| {
                serde_json::json!({
                    "_id": order.get_object_id("_id").ok().map(|id| id.to_hex()),
                    "orderNumber": order.get_str("orderNumber").unwrap_or("N/A"),
                    "userId": order.get_str("userId").unwrap_or(""),
                    "userEmail": order.get_str("userEmail").unwrap_or(""),
                    "userName": order.get_str("userName").unwrap_or("Guest"),
                    "items": order.get_array("items").ok().map(|items| {
                        items.iter().filter_map(|item| {
                            item.as_document().map(|doc| {
                                serde_json::json!({
                                    "productId": doc.get_str("productId").unwrap_or(""),
                                    "name": doc.get_str("name").unwrap_or(""),
                                    "image": doc.get_str("image").unwrap_or(""),
                                    "price": doc.get_f64("price").unwrap_or(0.0),
                                    "quantity": doc.get_i32("quantity").unwrap_or(0)
                                })
                            })
                        }).collect::<Vec<_>>()
                    }).unwrap_or_default(),
                    "subtotal": order.get_f64("subtotal").unwrap_or(0.0),
                    "tax": order.get_f64("tax").unwrap_or(0.0),
                    "deliveryFee": order.get_f64("deliveryFee").unwrap_or(0.0),
                    "total": order.get_f64("total").unwrap_or(0.0),
                    "status": order.get_str("status").unwrap_or("pending"),
                    "payment": order.get_str("payment").unwrap_or(""),
                    "delivery": order.get_document("delivery").ok().map(|doc| {
                        serde_json::json!({
                            "address": doc.get_str("address").unwrap_or(""),
                            "city": doc.get_str("city").unwrap_or(""),
                            "postalCode": doc.get_str("postalCode").ok(),
                            "phone": doc.get_str("phone").ok()
                        })
                    }).unwrap_or(serde_json::json!({})),
                    "coupon": order.get_document("coupon").ok().map(|doc| {
                        serde_json::json!({
                            "code": doc.get_str("code").unwrap_or(""),
                            "type": doc.get_str("type").unwrap_or(""),
                            "value": doc.get_f64("value").unwrap_or(0.0),
                            "discountAmount": doc.get_f64("discountAmount").unwrap_or(0.0)
                        })
                    }),
                    "createdAt": order.get_str("createdAt").unwrap_or(""),
                    "date": order.get_str("createdAt").unwrap_or("")
                })
            }).collect();
            
            println!("Found {} total orders", result.len());
            (StatusCode::OK, Json(result))
        }
        Err(e) => {
            eprintln!("Failed to fetch orders: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}

#[derive(Deserialize)]
struct UpdateStatusRequest {
    status: String,
}

async fn update_order_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateStatusRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Updating order {} status to {}", id, payload.status);
    
    let collection = state.db.collection::<Document>("orders");
    
    let object_id = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid order ID".into()
            }));
        }
    };
    
    match collection.update_one(
        doc! { "_id": object_id },
        doc! { "$set": { "status": &payload.status } },
        None
    ).await {
        Ok(result) => {
            if result.matched_count > 0 {
                println!("Order status updated successfully");
                (StatusCode::OK, Json(ApiResponse {
                    message: "Order status updated successfully".into()
                }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Order not found".into()
                }))
            }
        }
        Err(e) => {
            eprintln!("Failed to update order status: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to update order status".into()
            }))
        }
    }
}

async fn delete_order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse>) {
    println!("Deleting order: {}", id);
    
    let collection = state.db.collection::<Document>("orders");
    
    let object_id = match mongodb::bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                message: "Invalid order ID".into()
            }));
        }
    };
    
    match collection.delete_one(doc! { "_id": object_id }, None).await {
        Ok(result) => {
            if result.deleted_count > 0 {
                println!("Order deleted successfully");
                (StatusCode::OK, Json(ApiResponse {
                    message: "Order deleted successfully".into()
                }))
            } else {
                (StatusCode::NOT_FOUND, Json(ApiResponse {
                    message: "Order not found".into()
                }))
            }
        }
        Err(e) => {
            eprintln!("Failed to delete order: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to delete order".into()
            }))
        }
    }
}