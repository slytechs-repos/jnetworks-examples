/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnetworks.api.examples;

import static java.nio.file.StandardOpenOption.*;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;

import com.slytechs.jnet.jnetworks.api.NetException;
import com.slytechs.jnet.jnetworks.api.NetWorks;
import com.slytechs.jnet.jnetworks.api.PortId;
import com.slytechs.jnet.jnetworks.api.net.NetBuffer.CaptureBuffer;
import com.slytechs.jnet.jnetworks.api.net.NetCapture;
import com.slytechs.jnet.jnetworks.api.net.NetFileCapture.FileHeader;
import com.slytechs.jnet.jnetworks.api.net.NetSegment;
import com.slytechs.jnet.jnetworks.pcap.PcapWorks;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;

/**
 * A demonstration program for capturing network packets to a PCAP file using the jNetWorks SDK.
 * <p>
 * This class showcases high-performance packet capture capabilities, leveraging the jNetWorks SDK's
 * compatibility with PCAP, Napatech SmartNIC, and Intel's DPDK drivers and hardware. The program
 * initializes a capture session, configures traffic filters, captures packet segments, and writes
 * them to a PCAP file ({@code capture.pcap}). It uses a simplified, Java-based API to abstract
 * low-level network operations, making it suitable for developers working with high-speed network
 * interfaces.
 * </p>
 * <p>
 * The program performs the following steps:
 * <ol>
 * <li>Initializes the jNetWorks SDK with {@link PcapWorks}.</li>
 * <li>Creates a receive buffer for storing captured packets.</li>
 * <li>Generates a PCAP file header based on the output file extension.</li>
 * <li>Opens a capture session and file channel for writing to disk.</li>
 * <li>Configures capture settings, including traffic filters and packet descriptors.</li>
 * <li>Writes the PCAP file header to the output file.</li>
 * <li>Captures and writes packet segments to the file, releasing them after processing.</li>
 * <li>Automatically closes resources using try-with-resources.</li>
 * </ol>
 * </p>
 * <p>
 * <b>Prerequisites:</b>
 * <ul>
 * <li><b>jNetWorks SDK</b>: Must be installed and configured.</li>
 * <li><b>Network Interface</b>: A compatible interface (e.g., Napatech SmartNIC or Intel DPDK-supported hardware) must be available.</li>
 * <li><b>Host Buffers</b>: Sufficient receive (RX) host buffers must be configured for high-speed capture.</li>
 * <li><b>Java Environment</b>: A compatible Java runtime environment.</li>
 * <li><b>Write Permissions</b>: Required for creating and writing to the output PCAP file.</li>
 * </ul>
 * </p>
 * <p>
 * <b>Output:</b> The program generates a {@code capture.pcap} file containing a PCAP file header
 * and captured packet segments, which can be analyzed using tools like Wireshark or tcpdump.
 * </p>
 * <p>
 * <b>Usage Notes:</b>
 * <ul>
 * <li>Modify the {@code portFilter} range to capture traffic from different ports.</li>
 * <li>The {@code color(7)} setting is SDK-specific and may relate to packet prioritization; consult the jNetWorks SDK documentation.</li>
 * <li>Ensure sufficient system resources (e.g., memory, CPU) for high-speed capture.</li>
 * <li>Handle exceptions ({@link NetException}, {@link IOException}) appropriately in production code.</li>
 * </ul>
 * </p>
 *
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class CaptureExample {

    /**
     * Main method to execute the packet capture demonstration.
     * <p>
     * This method orchestrates the entire capture process, from initializing the jNetWorks SDK
     * to capturing and writing packet segments to a PCAP file. It uses try-with-resources to
     * ensure proper resource management and handles exceptions that may arise during network
     * operations or file I/O. The capture is configured to capture all traffic from ports 0 to 64,
     * using the PCAP descriptor format, and writes the output to {@code capture.pcap}.
     * </p>
     * <p>
     * <b>Steps Performed:</b>
     * <ol>
     * <li><b>Initialize SDK</b>: Creates a {@link PcapWorks} instance to access jNetWorks functionality.</li>
     * <li><b>Create Buffer</b>: Allocates a {@link CaptureBuffer} for storing packet segments.</li>
     * <li><b>Create File Header</b>: Generates a PCAP file header based on the output file extension.</li>
     * <li><b>Open Capture and File</b>: Opens a {@link NetCapture} session and a {@link FileChannel} for disk I/O.</li>
     * <li><b>Configure Capture</b>: Sets traffic filters, port ranges, color, and descriptor type.</li>
     * <li><b>Write Header</b>: Writes the PCAP file header to the output file.</li>
     * <li><b>Capture Segments</b>: Iteratively captures, writes, and releases packet segments.</li>
     * <li><b>Cleanup</b>: Automatically closes resources via try-with-resources.</li>
     * </ol>
     * </p>
     * <p>
     * <b>Example Output:</b> A {@code capture.pcap} file containing a PCAP header and packet segments
     * from ports 0 to 64, compatible with tools like Wireshark.
     * </p>
     *
     * @param args Command-line arguments (not used in this example).
     * @throws InterruptedException If the capture process is interrupted.
     * @throws NetException If a network-related error occurs during capture or configuration.
     * @throws IOException If an I/O error occurs while writing to the PCAP file.
     */
    public static void main(String[] args) throws InterruptedException, NetException, IOException {

        // Define the output PCAP file name and path
        final String filename = "capture.pcap";
        final Path file = new File(filename).toPath();

        // Step 1: Initialize the jNetWorks SDK
        // The PcapWorks class provides access to high-performance capture capabilities,
        // compatible with PCAP, Napatech SmartNIC, and Intel DPDK hardware.
        try (NetWorks networks = new PcapWorks()) {

            // Step 2: Create a receive buffer
            // Allocates a CaptureBuffer to store packet segments before writing to disk.
            // The buffer is associated with the output file name for streamlined processing.
            CaptureBuffer rxBuffer = networks.createRxBuffer(filename);

            // Step 3: Generate a PCAP file header
            // Determines the file format from the '.pcap' extension and creates a header
            // containing metadata required for the PCAP file.
            FileHeader fileHeader = networks.getFileFormatForExt(filename)
                    .createFileHeader();

            // Step 4: Open capture session and file channel
            // Opens a NetCapture session for packet capture and a FileChannel for writing
            // to the PCAP file. Try-with-resources ensures both are closed properly.
            try (NetCapture capture = networks.openCapture(rxBuffer);
                    FileChannel channel = FileChannel.open(file, WRITE, CREATE)) {

                // Step 5: Configure capture settings
                // Configures the capture to:
                // - Capture all traffic ("all")
                // - Filter ports 0 to 64
                // - Assign a color value (7) for prioritization or classification
                // - Use PCAP-compatible packet descriptors
                capture.assignTraffic("all")
                        .portFilter(PortId.portRange(0, 64))
                        .color(7)
                        .descriptor(PacketDescriptorType.PCAP);

                // Step 6: Write the PCAP file header
                // Writes the file header to the beginning of the PCAP file, initializing
                // it for packet data. The header is converted to a ByteBuffer for writing.
                channel.write(fileHeader.asByteBuffer());

                // Step 7: Capture and write packet segments
                // Iteratively captures segments from the receive buffer, writes them to the
                // PCAP file, and releases them to free buffer space.
                while (rxBuffer.hasRemaining()) {
                    NetSegment segment = rxBuffer.take();

                    // Write the segment to the PCAP file as a ByteBuffer
                    channel.write(segment.asByteBuffer());

                    // Release the segment to free memory
                    rxBuffer.release(segment);
                }
            } // Step 8: Close capture session and file channel
            // Resources are automatically closed by try-with-resources, ensuring no leaks.
        }
    }
}