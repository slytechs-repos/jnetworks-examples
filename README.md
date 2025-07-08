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
- `BypassConfigExample.java` - Configures bypass settings.
- `BypassInfoExample.java` - Provides bypass information.
- `BypassWatchdogExample.java` - Implements watchdog functionality for bypass.
- `ConfigEventExample.java` - Handles configuration events.
- `EventMonitorExample.java` - Monitors network events.
- `FlowLearnSpanExample.java` - Learns flow and spans network traffic.
- `FlowMatchExample.java` - Matches network flows.
- `HashCalcSingleExample.java` - Calculates single hash values.
- `InfoExample.java` - Provides network information.
- `AnalysisExample.java` - Performs network traffic analysis.
- `CapFileConvertExample.java` - Converts capture files.
- `ChecksumExample.java` - Computes packet checksums.
- `HostBufferPollExample.java` - Polls host buffers.
- `InlineExample.java` - Processes inline operations.
- `InfoDemoExample.java` - Showcases an information demonstration.
- `PreDemoExample.java` - Provides a pre-processing demonstration.
- `NumaExample.java` - Explores NUMA (Non-Uniform Memory Access) usage.
- `ReadCapFileExample.java` - Reads capture files.
- `ReplayExample.java` - Replays captured packets.
- `Replay4GExample.java` - Replays packets with 4G support.
- `ReplayWithTimestampInjectExample.java` - Replays packets with timestamp injection.
- `SegmentInlineExample.java` - Processes segments inline.
- `StreamIdStatisticsExample.java` - Gathers stream ID statistics.
- `TimestampInjectExample.java` - Injects timestamps into packets.
- `TransmitMultiFunctionExample.java` - Handles multi-function transmission.
- `TransmitOnTimestampExample.java` - Transmits based on timestamps.
- `TransmitOnTimestampSetClockExample.java` - Sets clock for timestamp-based transmission.
- `TransmitPcapExample.java` - Transmits PCAP file contents.
- `TransmitSegmentExample.java` - Transmits packet segments.
- `TransmitSegmentDynDescrExample.java` - Uses dynamic descriptors for segment transmission.
- `VlanDemoExample.java` - Demonstrates VLAN (Virtual Local Area Network) handling.
- `PpsExample.java` - Measures packets per second.
- `SensorExample.java` - Utilizes sensor data in networking.
- `StatExample.java` - Displays network statistics.
- `StatUsageExample.java` - Shows resource usage statistics.

## Getting Started

### Prerequisites
- **Java Development Kit (JDK)**: Version 11 or higher.
- **jNetWorks SDK**: Install from the official source (consult the jNetWorks documentation).
- **Compatible Hardware**: Optional Napatech SmartNIC or Intel DPDK-compatible hardware for enhanced performance.
- **Build Tools**: Use Maven or Gradle for building.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/jnetworks-sdk-examples.git
   cd jnetworks-sdk-examples
   ```
2. Add the jNetWorks SDK to your project dependencies (via Maven or manually include JAR files).
3. Compile and run the examples with your preferred Java build tool or IDE.

### Running an Example
To run the `CaptureExample.java`:
```bash
javac -cp path/to/jnetworks-sdk.jar com/slytechs/jnet/jnetworks/tests/CaptureExample.java
java -cp .:path/to/jnetworks-sdk.jar com.slytechs.jnet.jnetworks.tests.CaptureExample
```
Ensure the jNetWorks SDK is properly configured and permissions are in place.

## Contributing

Contributions are welcome to enhance this repository. To add a new example or improve an existing one:
1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Add your example under the appropriate package (e.g., `com.slytechs.jnet.jnetworks.tests`).
4. Include detailed Javadoc comments and update the README with the new example.
5. Submit a pull request with a clear description of your changes.

## License

This repository is licensed under the **Sly Technologies Free License**. See the license header in each example file or visit [http://www.slytechs.com/free-license-text](http://www.slytechs.com/free-license-text) for details.

## Contact

For questions or support, contact the maintainers:
- **Mark Bednarczyk**: mark@slytechs.com
- **Sly Technologies Inc.**: [Your contact info or website]

## Acknowledgments

Credit to the jNetWorks SDK team for providing a robust framework. This repository builds on their work to deliver Java-based examples for the community.