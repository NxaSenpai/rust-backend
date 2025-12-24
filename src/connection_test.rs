use mongodb::{Client, bson::{DateTime, to_document}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    pub name: String,
    pub password: String,
    pub email: String,
    pub date: String,
}

impl User {
    pub fn new(name: String, password: String, email: String, date: String) -> Self {
        User { name, password, email, date }
    }

    pub fn println(&self) {
        println!("Name: {}, Email: {}, Date: {}", self.name, self.email, self.date);
    }
}

pub async fn test_db() {
    let client: Client = Client::with_uri_str("mongodb://localhost:27017").await.unwrap();
    let db: mongodb::Database = client.database("StarTechDB");
    let collection = db.collection::<mongodb::bson::Document>("users");

    let new_user = User {
        name: "Baba".to_string(),
        password: "123".to_string(),
        email: "baba1@gmail.com".to_string(),
        date: DateTime::now().to_string(),
    };

    match collection.insert_one(to_document(&new_user).unwrap(), None).await {
        Ok(insert_result) => {
            println!("Inserted document with id: {:?}", insert_result.inserted_id);
        }
        Err(e) => {
            eprintln!("Error inserting document: {:?}", e);
        }
    }
}