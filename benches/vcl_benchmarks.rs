use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use vcl_protocol::crypto::{KeyPair, encrypt_payload, decrypt_payload};
use vcl_protocol::packet::VCLPacket;

// ─── Crypto benchmarks ───────────────────────────────────────────────────────

fn bench_keypair_generate(c: &mut Criterion) {
    c.bench_function("keypair_generate", |b| {
        b.iter(|| KeyPair::generate())
    });
}

fn bench_encrypt_payload(c: &mut Criterion) {
    let key = [1u8; 32];
    let mut group = c.benchmark_group("encrypt_payload");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| encrypt_payload(&data, &key).unwrap())
        });
    }
    group.finish();
}

fn bench_decrypt_payload(c: &mut Criterion) {
    let key = [1u8; 32];
    let mut group = c.benchmark_group("decrypt_payload");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        let (ciphertext, nonce) = encrypt_payload(&data, &key).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| decrypt_payload(&ciphertext, &key, &nonce).unwrap())
        });
    }
    group.finish();
}

// ─── Packet benchmarks ───────────────────────────────────────────────────────

fn bench_packet_sign(c: &mut Criterion) {
    let kp = KeyPair::generate();
    c.bench_function("packet_sign", |b| {
        b.iter(|| {
            let mut packet = VCLPacket::new(0, vec![0; 32], b"benchmark payload".to_vec(), [0; 24]);
            packet.sign(&kp.private_key).unwrap();
        })
    });
}

fn bench_packet_verify(c: &mut Criterion) {
    let kp = KeyPair::generate();
    let mut packet = VCLPacket::new(0, vec![0; 32], b"benchmark payload".to_vec(), [0; 24]);
    packet.sign(&kp.private_key).unwrap();

    c.bench_function("packet_verify", |b| {
        b.iter(|| packet.verify(&kp.public_key).unwrap())
    });
}

fn bench_packet_serialize(c: &mut Criterion) {
    let kp = KeyPair::generate();
    let mut packet = VCLPacket::new(0, vec![0; 32], vec![0u8; 1024], [0; 24]);
    packet.sign(&kp.private_key).unwrap();

    c.bench_function("packet_serialize", |b| {
        b.iter(|| packet.serialize())
    });
}

fn bench_packet_deserialize(c: &mut Criterion) {
    let kp = KeyPair::generate();
    let mut packet = VCLPacket::new(0, vec![0; 32], vec![0u8; 1024], [0; 24]);
    packet.sign(&kp.private_key).unwrap();
    let bytes = packet.serialize();

    c.bench_function("packet_deserialize", |b| {
        b.iter(|| VCLPacket::deserialize(&bytes).unwrap())
    });
}

fn bench_packet_compute_hash(c: &mut Criterion) {
    let packet = VCLPacket::new(0, vec![0; 32], vec![0u8; 1024], [0; 24]);

    c.bench_function("packet_compute_hash", |b| {
        b.iter(|| packet.compute_hash())
    });
}

// ─── Full pipeline benchmark ─────────────────────────────────────────────────

fn bench_full_pipeline(c: &mut Criterion) {
    let key = [1u8; 32];
    let kp = KeyPair::generate();
    let mut group = c.benchmark_group("full_pipeline");

    for size in [64, 1024, 4096].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(
            BenchmarkId::new("encrypt_sign_serialize", size),
            size,
            |b, _| {
                b.iter(|| {
                    let (encrypted, nonce) = encrypt_payload(&data, &key).unwrap();
                    let mut packet = VCLPacket::new(0, vec![0; 32], encrypted, nonce);
                    packet.sign(&kp.private_key).unwrap();
                    packet.serialize()
                })
            },
        );

        let (encrypted, nonce) = encrypt_payload(&data, &key).unwrap();
        let mut packet = VCLPacket::new(0, vec![0; 32], encrypted, nonce);
        packet.sign(&kp.private_key).unwrap();
        let bytes = packet.serialize();

        group.bench_with_input(
            BenchmarkId::new("deserialize_verify_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    let p = VCLPacket::deserialize(&bytes).unwrap();
                    p.verify(&kp.public_key).unwrap();
                    decrypt_payload(&p.payload, &key, &p.nonce).unwrap()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_keypair_generate,
    bench_encrypt_payload,
    bench_decrypt_payload,
    bench_packet_sign,
    bench_packet_verify,
    bench_packet_serialize,
    bench_packet_deserialize,
    bench_packet_compute_hash,
    bench_full_pipeline,
);
criterion_main!(benches);
