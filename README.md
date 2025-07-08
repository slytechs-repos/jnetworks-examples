# jNetWorks SDK Examples

Welcome to the **jNetWorks SDK Examples** repository. This repository hosts a collection of example programs demonstrating the jNetWorks SDK, a Java-based library for high-performance network packet capture, processing, and transmission. The jNetWorks SDK is compatible with PCAP, Napatech SmartNIC, and Intel's DPDK drivers and hardware, offering a robust, object-oriented solution for network programming.

## Overview

These examples illustrate the jNetWorks SDK’s capabilities across various network tasks. Written in Java, they utilize the SDK’s streamlined API to manage low-level network operations while supporting advanced hardware. The repository serves as a valuable resource for developers building network applications.

## Current Examples

### Capture Example
- **File**: `com.slytechs.jnet.jnetworks.tests/CaptureExample.java`
- **Description**: Captures network packets and saves them to a PCAP file.

### Retransmit File Example
- **File**: `com.slytechs.jnet.jnetworks.tests/RetransmitFileExample.java`
- **Description**: Retransmits packets from a PCAP file over a network interface.

## Planned Examples

The following examples will be added to expand the repository’s coverage of network programming use cases with the jNetWorks SDK in Java:
- `TransmitPacketExample.java` - Transmits packets using the packet interface, sending 2,500,000 packets of 1024 bytes from port 0 with an incrementing 32-bit pattern.
- `TransmitPcapExample.java` - Transmits PCAP packets using the packet interface, sending 2,500,000 packets of 1024 bytes from port 0 with an incrementing 32-bit pattern, supporting transmit on timestamp or segment interfaces with the "forceTxOnTs" feature enabled for timestamp mode.
- `VlanDemoExample.java` - Implements VLAN tagging for received packets using 4GA inline capabilities, adding a VLAN tag before forwarding.
- `PpsExample.java` - Utilizes PPS (Packets Per Second) functionality.
- `StatExample.java` - Uses the statistics stream interface to manage network statistics.
- `StatUsageExample.java` - Uses the statistics stream interface to read hostbuffer usage statistics.
- `SensorExample.java` - Employs the Info stream interface for sensor data.
- `TransmitOnTimestampExample.java` - Transmits packets on timestamp using the packet interface, sending 100,000 packets of 296 bytes from port 0 at approximately 5 Mb/s with an incrementing 32-bit pattern, also available in segment mode.
- `TimestampInjectExample.java` - Controls TX timestamp injection and FCS generation per packet using dynamic descriptor 3, transmitting six packet variations (no timestamp/no change, no timestamp/good FCS, no timestamp/bad FCS, timestamp/no change, timestamp/good FCS, timestamp/bad FCS) in a loop, with RX checking latency and dumping packets.
- `SegmentInlineExample.java` - Performs inline processing with the segment interface.
- `ReplayExample.java` - Replays a capture file onto a port.
- `ReadCapFileExample.java` - Reads a capture file, operational without NTservice.
- `NumaExample.java` - Utilizes host buffers allocated to a specific NUMA node, applicable to Linux, using host buffers on NUMA node 1 and receiving data on port 0.
- `NetflowExample.java` - Extracts NetFlow information from packets using the Type1 descriptor.
- `IpfdemoExample.java` - Implements IP fragment re-assembling using FPGA IPFMode, accelerating load balancing with a 5-tuple hash algorithm and handling un-matched fragments.
- `HostBufferPollExample.java` - Polls for NetBuffer attachment.
- `ChecksumExample.java` - Transmits 10 packets with L3/L4 checksum calculation controlled via packet descriptor bits, defaulting to adapter-recalculated checksums.
- `CapFileConvertExample.java` - Converts capture files.
- `InfoExample.java` - Retrieves and displays adapter information, including serial number, hardware/FPGA version, and PCI identifier, using the Info stream interface.
- `EventMonitorExample.java` - Monitors events in an infinite loop, printing events and translating sensor data into text.

## Getting Started

### Prerequisites
- **Java Development Kit (JDK)**: Version 22 or higher.
- **jNetWorks SDK**: Install from the git repository (slytechs-repos) or Maven Central repository.
- **Compatible Hardware**: Optional Napatech SmartNIC or Intel DPDK-compatible hardware for enhanced performance.
- **Build Tools**: Use Maven or Gradle for building.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/slytechs-repos/jnetworks-sdk-examples.git
   cd jnetworks-sdk-examples
   ```
2. Add the jNetWorks SDK to your project dependencies (via Maven or manually include JAR files).
3. Compile and run the examples with your preferred Java build tool or IDE.

### Running an Example
To run the `CaptureExample.java`:
```bash
javac -mp path/to/jnetworks-sdk.jar com/slytechs/jnet/jnetworks/tests/CaptureExample.java
java -mp .:path/to/jnetworks-sdk.jar com.slytechs.jnet.jnetworks.tests.CaptureExample
```
Ensure the jNetWorks SDK is properly configured and permissions are in place.

## License

This repository is licensed under the **Sly Technologies Free License**. See the license header in each example file or visit [http://www.slytechs.com/free-license-text](http://www.slytechs.com/free-license-text) for details.

## Contact

For questions or support, contact the maintainers:
- **Support**: support@slytechs.com
- **Sales**: sales@slytechs.com
- **Sly Technologies Inc.**: www.slytechs.com

## Acknowledgments

Credit to the jNetWorks SDK team for providing a robust framework. This repository builds on their work to deliver Java-based examples for the community.