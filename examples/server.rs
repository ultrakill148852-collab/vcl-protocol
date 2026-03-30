use vcl_protocol::connection::VCLConnection;

#[tokio::main]
async fn main() {
    // ← ДОБАВЬ ЭТО:
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
    server.set_shared_key(&shared_key);  // ← ДОБАВЬ ЭТО
    
    println!("Server started on 127.0.0.1:8080");
    
    println!("Waiting for client handshake...");
    server.accept_handshake().await.unwrap();
    println!("Client connected! Handshake completed.");
    
    for i in 1..=5 {
        match server.recv().await {
            Ok(packet) => {
                let msg = String::from_utf8_lossy(&packet.payload);
                println!("Received message {}: {}", i, msg);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
    
    println!("Server finished");
}
