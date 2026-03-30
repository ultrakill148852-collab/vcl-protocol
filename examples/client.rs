use vcl_protocol::connection::VCLConnection;

#[tokio::main]
async fn main() {
    // ← ДОБАВЬ ЭТО:
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);  // ← ДОБАВЬ ЭТО
    
    println!("Connecting to server...");
    client.connect("127.0.0.1:8080").await.unwrap();
    println!("Connected! Handshake completed.");
    
    for i in 1..=5 {
        let msg = format!("Message {}", i);
        client.send(msg.as_bytes()).await.unwrap();
        println!("Sent: {}", msg);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    client.close().unwrap();
    println!("Connection closed");
}
