# PrivateLayer

Minimal mesh WireGuard VPN implementation in Go.

## Architecture

- **Control Plane**: Central coordination server that manages peer discovery and registration
- **Client**: Mesh node that connects to control plane and establishes WireGuard tunnels

## Building

```bash
go build -o bin/controlplane.exe ./cmd/controlplane
go build -o bin/client.exe ./cmd/client
```

## Usage

1. Start the control plane:
```bash
./bin/controlplane.exe -port 8080
```

2. Start clients on each node:
```bash
./bin/client.exe -control localhost:8080 -iface wg0
```

## Components

- `internal/wireguard`: Key generation and interface configuration
- `internal/mesh`: Mesh coordination and peer management
- `internal/client`: Client library for mesh nodes

## Features

- Automatic WireGuard key generation
- Peer discovery via control plane
- Heartbeat-based peer health monitoring
- Dynamic peer updates

## License

WireGuard is a registered trademark of Jason A. Donenfeld. The software is copyrighted and released under the GNU General Public License v2.

This project is licensed under the [GNU General Public License 3.0](license.md).