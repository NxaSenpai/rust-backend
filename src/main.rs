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
        fs::create_dir_all(upload_dir).expect("Failed to create uploads directory");
    }

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
        .route("/users", get(get_users_by_role))
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
        .route("/products", get(get_products))
        .route("/products", post(create_product))
        .route("/products/:id", patch(update_product))
        .route("/products/:id", delete(delete_product))
        .route("/products/bulk-delete", post(bulk_delete_products))
        .route("/upload-image", post(upload_image))
        .nest_service("/uploads", ServeDir::new("uploads"))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
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
    let collection = state.db.collection::<Product>("products");
    
    payload.stock_at = Some(chrono::Utc::now().format("%a, %b %d, %Y").to_string());
    payload.id = None;
    
    let category = payload.category.clone();
    let supplier = payload.supplier.clone();
    
    match collection.insert_one(&payload, None).await {
        Ok(result) => {
            println!("Product created with ID: {:?}", result.inserted_id);
            
            if let Err(e) = update_category_product_count(&state.db, &category, 1).await {
                eprintln!("Failed to update category count: {:?}", e);
            }
            
            if let Err(e) = update_supplier_product_count(&state.db, &supplier, 1).await {
                eprintln!("Failed to update supplier count: {:?}", e);
            }
            
            (StatusCode::CREATED, Json(ApiResponse { message: "Product created".into() }))
        }
        Err(e) => {
            eprintln!("create_product error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse { 
                message: format!("Failed to create product: {}", e) 
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
    message: String,
    #[serde(rename = "imagePath")]
    image_path: String,
}

async fn upload_image(
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ApiResponse>)> {
    let upload_dir = "uploads";
    if !StdPath::new(upload_dir).exists() {
        fs::create_dir_all(upload_dir).map_err(|e| {
            eprintln!("Failed to create upload directory: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                message: "Failed to create upload directory".into()
            }))
        })?;
    }

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("file").to_string();
        let filename = field.file_name().unwrap_or("unknown").to_string();
        let data = field.bytes().await.unwrap();

        if name == "image" {
            let timestamp = chrono::Utc::now().timestamp();
            let ext = StdPath::new(&filename)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("png");
            let unique_filename = format!("product_{}_{}.{}", timestamp, rand::random::<u32>(), ext);
            let filepath = format!("{}/{}", upload_dir, unique_filename);

            fs::write(&filepath, &data).map_err(|e| {
                eprintln!("Failed to save file: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
                    message: "Failed to save file".into()
                }))
            })?;

            println!("File uploaded: {}", filepath);

            return Ok(Json(UploadResponse {
                message: "Image uploaded successfully".into(),
                image_path: format!("http://localhost:3000/uploads/{}", unique_filename),
            }));
        }
    }

    Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
        message: "No image file provided".into()
    })))
}

#[derive(Serialize)]
struct UserListResponse {
    #[serde(rename = "_id")]
    id: String,
    name: String,
    email: String,
    role: String,
    #[serde(rename = "joinSince")]
    join_since: String,
}

async fn get_users_by_role(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Vec<UserListResponse>>) {
    println!("GET /users called");
    
    let role = params.get("role").map(|s| s.as_str()).unwrap_or("user");
    println!("Filtering by role: {}", role);
    
    let collection = state.db.collection::<Document>("users");
    
    let filter = doc! { "role": role };
    
    match collection.find(filter, None).await {
        Ok(cursor) => {
            let users: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
            println!("Found {} users with role '{}'", users.len(), role);
            
            let responses: Vec<UserListResponse> = users.into_iter().map(|doc| {
                let id = doc.get_object_id("_id")
                    .map(|oid| oid.to_hex())
                    .unwrap_or_default();
                let name = doc.get_str("name").unwrap_or("Unknown").to_string();
                let email = doc.get_str("email").unwrap_or("").to_string();
                let role = doc.get_str("role").unwrap_or("user").to_string();
                let join_since = doc.get_str("date").unwrap_or("N/A").to_string();
                
                let formatted_date = if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&join_since) {
                    parsed.format("%Y-%m-%d").to_string()
                } else {
                    join_since
                };
                
                UserListResponse {
                    id,
                    name,
                    email,
                    role,
                    join_since: formatted_date,
                }
            }).collect();
            
            (StatusCode::OK, Json(responses))
        }
        Err(e) => {
            eprintln!("get_users error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]))
        }
    }
}