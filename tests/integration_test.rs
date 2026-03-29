use vcl_protocol::connection::VCLConnection;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_client_server_basic() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:9001").await.unwrap();
    server.set_shared_key(&shared_key);
    
    let server_handle = tokio::spawn(async move {
        server.accept_handshake().await.unwrap();
        for i in 1..=3 {
            let packet = server.recv().await.unwrap();
            assert_eq!(packet.payload, format!("msg{}", i).as_bytes());
        }
    });
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    client.connect("127.0.0.1:9001").await.unwrap();
    
    for i in 1..=3 {
        client.send(format!("msg{}", i).as_bytes()).await.unwrap();
        sleep(Duration::from_millis(50)).await;
    }
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_encryption_integrity() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:9002").await.unwrap();
    server.set_shared_key(&shared_key);
    
    let server_handle = tokio::spawn(async move {
        server.accept_handshake().await.unwrap();
        let packet = server.recv().await.unwrap();
        assert_eq!(packet.payload, b"secret");
    });
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    client.connect("127.0.0.1:9002").await.unwrap();
    client.send(b"secret").await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_chain_validation() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:9003").await.unwrap();
    server.set_shared_key(&shared_key);
    
    let server_handle = tokio::spawn(async move {
        server.accept_handshake().await.unwrap();
        let p1 = server.recv().await.unwrap();
        assert_eq!(p1.sequence, 0);
        let p2 = server.recv().await.unwrap();
        assert_eq!(p2.sequence, 1);
    });
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    client.connect("127.0.0.1:9003").await.unwrap();
    client.send(b"first").await.unwrap();
    client.send(b"second").await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_replay_protection() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000004").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:9004").await.unwrap();
    server.set_shared_key(&shared_key);
    
    let server_handle = tokio::spawn(async move {
        server.accept_handshake().await.unwrap();
        
        let p1 = server.recv().await.unwrap();
        assert_eq!(p1.sequence, 0);
        
        let p2 = server.recv().await.unwrap();
        assert_eq!(p2.sequence, 1);
    });
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    client.connect("127.0.0.1:9004").await.unwrap();
    
    client.send(b"first").await.unwrap();
    client.send(b"second").await.unwrap();
    
    server_handle.await.unwrap();
}
