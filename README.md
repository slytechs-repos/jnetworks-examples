# jNetWorks SDK Examples

Example programs demonstrating the **jNetWorks SDK v3**, a high-performance Java framework for multi-CPU packet capture and protocol analysis. Supports libpcap, DPDK, and Napatech SmartNIC backends.

## Overview

jNetWorks v3 introduces a channel-based API with acquire/release semantics, parallel processing via TaskScope, and clean session lifecycle management. These examples demonstrate the core patterns.

## Current Examples

### HelloCapture

- **File**: `com.slytechs.sdk.jnetworks.examples.HelloCapture`
- **Description**: Minimal packet capture demonstrating the channel API
- **Concepts**: Backend creation, channel setup, TaskScope, acquire/release pattern

```java
try (Net net = new PcapBackend()) {
    PacketChannel channel = net.packetChannel("capture", settings, stack);
    
    net.capture("main", "en0")
        .filter("tcp")
        .assignTo(channel)
        .apply();
    
    try (TaskScope scope = new TaskScope(net)) {
        scope.shutdownAfter(Duration.ofSeconds(10));
        scope.fork(channel, this::processPackets);
        scope.awaitCompletion();
    }
}
```

## Planned Examples

| Example                | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| `ParallelCapture`      | Multi-channel parallel processing with 5-tuple hash distribution |
| `BiDirectionalForward` | ICMP forwarding bridge with TX offload                       |
| `ProtocolFilter`       | Protocol-specific channel (TCP segments, HTTP messages)      |
| `BufferCapture`        | High-throughput bulk segment processing                      |
| `TokenStream`          | Token extraction for AI/ML analysis                          |
| `DpdkCapture`          | DPDK backend with LCORE affinity                             |
| `NapatechCapture`      | Napatech SmartNIC with hardware offloads                     |

## Key Concepts

### Channel Types

- **PacketChannel** - Single packet acquire/release
- **BufferChannel** - Bulk segment processing
- **ProtocolChannel** - Typed protocol objects (TcpSegment, HttpMessage)

### Session Lifecycle

```
Net (root session)
 ├── Channel Sessions
 ├── Capture Sessions  
 └── TaskScope (worker management)
      └── Task Sessions (per forked worker)
```

### Acquire/Release Pattern

```java
while (channel.isActive()) {
    Packet packet = channel.acquire();
    
    // Fast path - process and release
    process(packet);
    channel.release(packet);
    
    // Or persist if needed
    Packet copy = packet.persist();
    channel.release(packet);
    slowProcess(copy);
}
```

## Getting Started

### Prerequisites

- **JDK 22+** (virtual threads, FFM API)
- **jNetWorks SDK 3.0.0+**
- **libpcap** (for PcapBackend)

### Maven

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>jnetworks-sdk</artifactId>
    <version>3.0.0-SNAPSHOT</version>
    <type>pom</type>
</dependency>
```

### Running

```bash
# Build
mvn clean package

# Run HelloCapture
java -m com.slytechs.sdk.jnetworks.examples/com.slytechs.sdk.jnetworks.examples.HelloCapture
```

## Module Structure

```
jnetworks-sdk
├── jnetworks-api          - Core API (channels, capture, task)
├── jnetworks-pcap         - libpcap backend (Apache 2.0)
├── jnetworks-dpdk         - DPDK backend (Commercial)
├── jnetworks-ntapi        - Napatech backend (Commercial)
├── sdk-protocol-core      - Protocol dissection
└── sdk-protocol-tcpip     - TCP/IP protocol pack
```

## License

Apache License 2.0 - See [LICENSE](https://claude.ai/chat/LICENSE) for details.

## Resources

- **Documentation**: https://docs.slytechs.com/jnetworks
- **API Spec**: See `jnetworks-api-spec-v3.1.md`
- **Support**: support@slytechs.com
- **Website**: https://www.slytechs.com

## Status

🚧 **Work in Progress** - jNetWorks v3 API is under active development. Examples will be updated as the API stabilizes.