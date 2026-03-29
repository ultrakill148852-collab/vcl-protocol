mod packet;
mod crypto;
mod connection;
mod handshake;

use connection::VCLConnection;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("=== VCL Protocol Demo ===\n");

    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

    let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
    server.set_shared_key(&shared_key);
    println!("Server started on 127.0.0.1:8080");

    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    
    // Запускаем сервер в отдельной задаче
    let server_handle = tokio::spawn(async move {
        // Сервер принимает handshake
        match server.accept_handshake().await {
            Ok(_) => println!("Handshake completed"),
            Err(e) => println!("Handshake error: {}", e),
        }
        
        // Получаем 5 пакетов
        for i in 1..=5 {
            match server.recv().await {
                Ok(packet) => {
                    println!("Server received packet {}: {}", i, String::from_utf8_lossy(&packet.payload));
                }
                Err(e) => println!("Server error: {}", e),
            }
        }
    });

    // Клиент подключается
    client.connect("127.0.0.1:8080").await.unwrap();
    println!("Client connected (handshake complete)");

    // Клиент отправляет 5 пакетов
    for i in 1..=5 {
        let msg = format!("Message {}", i);
        client.send(msg.as_bytes()).await.unwrap();
        println!("Client sent: {}", msg);
        sleep(Duration::from_millis(100)).await;
    }

    server_handle.await.unwrap();
    println!("\n=== Demo Complete ===");
}
