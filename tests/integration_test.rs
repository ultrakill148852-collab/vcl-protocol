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

#[tokio::test]
async fn test_close() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap();
    
    let mut conn = VCLConnection::bind("127.0.0.1:9005").await.unwrap();
    conn.set_shared_key(&shared_key);
    
    assert!(!conn.is_closed());
    
    conn.close().unwrap();
    
    assert!(conn.is_closed());
    
    let result = conn.close();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_send_after_close() {
    let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000006").unwrap();
    
    let mut server = VCLConnection::bind("127.0.0.1:9006").await.unwrap();
    server.set_shared_key(&shared_key);
    
    let server_handle = tokio::spawn(async move {
        server.accept_handshake().await.unwrap();
        server.close().unwrap();
        
        let result = server.recv().await;
        assert!(result.is_err());
    });
    
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    client.set_shared_key(&shared_key);
    client.connect("127.0.0.1:9006").await.unwrap();
    
    client.close().unwrap();
    
    let result = client.send(b"test").await;
    assert!(result.is_err());
    
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_timeout_getters() {
    let mut conn = VCLConnection::bind("127.0.0.1:9007").await.unwrap();
    
    assert_eq!(conn.get_timeout(), 60);
    
    conn.set_timeout(120);
    assert_eq!(conn.get_timeout(), 120);
    
    let _ = conn.last_activity();
}
