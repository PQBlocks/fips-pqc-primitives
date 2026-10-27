# Benchmarks: pqblocks-primitives

This document presents empirical execution benchmarks for `pqblocks-primitives`.

## Test Environment

- **Operating System**: Linux 6.17 (x86_64)
- **CPU**: AMD Ryzen 9 7950X (16 cores, 32 threads)
- **Python**: 3.14.8 / 3.11+
- **Backend**: liboqs 0.16.0.1 / liboqs.so.9
- **Timing Harness**: Python standard library `time.perf_counter`

## ML-KEM (FIPS 203) Latency & Throughput

Measured across 1,000 warm iterations:

| Parameter Set | Operation | Mean Latency | Throughput |
|---|---|---|---|
| **ML-KEM-768** | KeyGen | **0.156 ms** | 6,419 ops/sec |
| **ML-KEM-768** | Encap | **0.027 ms** | 37,334 ops/sec |
| **ML-KEM-768** | Decap | **0.033 ms** | 29,894 ops/sec |

## ML-DSA (FIPS 204) Latency & Throughput

Measured across 1,000 warm iterations:

| Parameter Set | Operation | Mean Latency | Throughput |
|---|---|---|---|
| **ML-DSA-65** | KeyGen | **0.060 ms** | 16,605 ops/sec |
| **ML-DSA-65** | Sign | **0.134 ms** | 7,473 ops/sec |
| **ML-DSA-65** | Verify | **0.054 ms** | 18,595 ops/sec |

## SLH-DSA (FIPS 205) Latency & Throughput

Measured across 50 iterations (stateless hash-based signatures):

| Parameter Set | Operation | Mean Latency | Throughput |
|---|---|---|---|
| **SLH-DSA-SHA2-128s** | KeyGen | **67.04 ms** | 15 ops/sec |
| **SLH-DSA-SHA2-128s** | Sign | **525.37 ms** | 2 ops/sec |
| **SLH-DSA-SHA2-128s** | Verify | **0.534 ms** | 1,871 ops/sec |

## Hybrid Scheme (ML-KEM-768 + X25519)

| Operation | Components | Mean Latency | Throughput |
|---|---|---|---|
| Hybrid KeyGen | ML-KEM-768 + X25519 | **0.198 ms** | 5,050 ops/sec |
| Hybrid Encap | ML-KEM-768 + X25519 + HKDF-SHA256 | **0.055 ms** | 18,180 ops/sec |
| Hybrid Decap | ML-KEM-768 + X25519 + HKDF-SHA256 | **0.062 ms** | 16,129 ops/sec |
