# QNavi
Rust backend for ARNavi

## HTTP3/QUIC REST API

A high-performance REST API server built with Rust using HTTP/3 over QUIC protocol.

### Features

- **HTTP/3 Protocol**: Uses the latest HTTP/3 protocol over QUIC for better performance
- **REST API**: Full CRUD operations (GET, POST, PUT, DELETE)
- **In-Memory Storage**: Simple in-memory data store for demonstration
- **JSON Support**: All endpoints use JSON for data exchange
- **Async/Await**: Built with Tokio for high concurrency

### Building

```bash
cargo build --release
```

### Running

```bash
cargo run
```

The server will start on `https://127.0.0.1:4433` with a self-signed certificate.

### API Endpoints

#### List all items
```bash
GET /api/items
```

#### Get item by ID
```bash
GET /api/items/{id}
```

#### Create new item
```bash
POST /api/items
Content-Type: application/json

{
  "id": "2",
  "name": "New Item",
  "description": "Description of the item"
}
```

#### Update item
```bash
PUT /api/items/{id}
Content-Type: application/json

{
  "id": "2",
  "name": "Updated Item",
  "description": "Updated description"
}
```

#### Delete item
```bash
DELETE /api/items/{id}
```

### Testing

You can test the API using curl with HTTP/3 support:

```bash
# List items
curl --http3-only -k https://127.0.0.1:4433/api/items

# Get specific item
curl --http3-only -k https://127.0.0.1:4433/api/items/1

# Create item
curl --http3-only -k -X POST https://127.0.0.1:4433/api/items \
  -H "Content-Type: application/json" \
  -d '{"id":"2","name":"Test","description":"Test item"}'

# Update item
curl --http3-only -k -X PUT https://127.0.0.1:4433/api/items/2 \
  -H "Content-Type: application/json" \
  -d '{"id":"2","name":"Updated","description":"Updated item"}'

# Delete item
curl --http3-only -k -X DELETE https://127.0.0.1:4433/api/items/2
```

### Dependencies

- `tokio`: Async runtime
- `h3`: HTTP/3 implementation
- `h3-quinn`: QUIC integration for h3
- `quinn`: QUIC protocol implementation
- `rustls`: TLS library
- `rcgen`: Certificate generation
- `serde`: Serialization/deserialization
- `serde_json`: JSON support
- `tracing`: Logging and diagnostics

### Development

The server uses a self-signed certificate for HTTPS. In production, you should use a proper certificate from a trusted CA.

