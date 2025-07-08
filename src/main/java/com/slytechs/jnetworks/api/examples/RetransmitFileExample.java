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

import java.io.FileNotFoundException;

import com.slytechs.jnet.jnetworks.api.NetException;
import com.slytechs.jnet.jnetworks.api.NetWorks;
import com.slytechs.jnet.jnetworks.api.net.NetBuffer.FileBuffer;
import com.slytechs.jnet.jnetworks.api.net.NetBuffer.TransmitBuffer;
import com.slytechs.jnet.jnetworks.api.net.NetFileCapture;
import com.slytechs.jnet.jnetworks.api.net.NetSegment;
import com.slytechs.jnet.jnetworks.api.net.NetSegment.FileSegment;
import com.slytechs.jnet.jnetworks.api.net.NetTransmit;
import com.slytechs.jnet.jnetworks.pcap.PcapWorks;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.descriptor.TxAttributes;

/**
 * A demonstration program for retransmitting network packets from a PCAP file using the jNetWorks SDK.
 * <p>
 * This class showcases the jNetWorks SDK's capability to read packets from a PCAP file and retransmit them
 * over a network interface with precise timing control. The SDK, compatible with PCAP, Napatech SmartNIC,
 * and Intel's DPDK drivers and hardware, provides a high-performance Java-based API for network operations.
 * The example initializes buffers, configures a file capture and transmitter, and synchronizes transmission
 * with the first packet's timestamp to preserve inter-frame gaps.
 * </p>
 * <p>
 * <b>Prerequisites:</b>
 * <ul>
 * <li>jNetWorks SDK installed and configured.</li>
 * <li>A compatible network interface (e.g., Napatech SmartNIC or Intel DPDK-supported hardware).</li>
 * <li>Sufficient transmit (TX) host buffers configured.</li>
 * <li>A valid PCAP file (e.g., {@code capture.pcap}) with read permissions.</li>
 * <li>Java runtime environment (JDK 22 or higher).</li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Notes:</b>
 * <ul>
 * <li>Ensure the input PCAP file exists and contains valid packet data.</li>
 * <li>Adjust the {@code setTransmitImmediately(false)} setting for different timing behaviors.</li>
 * <li>Customize buffer names using the {@code %s} and {@code %d} placeholders as needed.</li>
 * <li>Verify sufficient system resources for high-speed transmission.</li>
 * <li>Handle exceptions ({@link FileNotFoundException}, {@link NetException}, {@link InterruptedException})
 * appropriately in production code.</li>
 * </ul>
 * </p>
 * <p>
 * <b>Output:</b> Retransmits all packets from the PCAP file over the network interface, preserving the
 * timing of the first packet and inter-frame gaps. The transmitted packets can be captured or analyzed
 * using network monitoring tools.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class RetransmitFileExample {

    /**
     * Main method to execute the packet retransmission demonstration.
     * <p>
     * This method orchestrates the retransmission process, reading packets from a PCAP file and transmitting
     * them over a network interface. It initializes the jNetWorks SDK, creates file and transmit buffers,
     * opens a file capture and transmitter, starts the transmission, and processes packet segments with
     * timing synchronization for the first packet. The process uses try-with-resources for automatic
     * resource management and handles potential exceptions.
     * </p>
     * <p>
     * <b>Steps Performed:</b>
     * <ol>
     * <li>Initializes the jNetWorks SDK with {@link PcapWorks}.</li>
     * <li>Creates a {@link FileBuffer} for reading PCAP file data and a {@link TransmitBuffer} for transmission.</li>
     * <li>Opens a {@link NetFileCapture} session for the PCAP file and a {@link NetTransmit} session.</li>
     * <li>Starts the transmitter to begin packet transmission.</li>
     * <li>Processes packet segments, copying data from the file buffer to the transmit buffer, synchronizing
     * the clock with the first packet's timestamp, and releasing segments for transmission.</li>
     * <li>Automatically closes resources using try-with-resources.</li>
     * </ol>
     * </p>
     * <p>
     * <b>Configuration:</b> The first packet's transmission is synchronized with its timestamp, and
     * inter-frame gaps are preserved by setting {@code setTransmitImmediately(false)}. Subsequent packets
     * follow the initial timing.
     * </p>
     *
     * @param args Command-line arguments (not used in this example).
     * @throws FileNotFoundException If the specified PCAP file (e.g., {@code capture.pcap}) is not found.
     * @throws NetException If a network-related error occurs during capture or transmission setup.
     * @throws InterruptedException If the thread is interrupted while waiting for transmission.
     */
    public static void main(String[] args) throws FileNotFoundException, NetException, InterruptedException {
        // Define the input PCAP file name
        final String filename = "capture.pcap";

        // Step 1: Initialize the jNetWorks SDK
        // Uses PcapWorks to enable high-performance packet handling compatible with PCAP and advanced hardware.
        try (NetWorks networks = new PcapWorks()) {

            // Step 2: Create file and transmit buffers
            // Allocates a FileBuffer for reading PCAP data and a TransmitBuffer for sending packets,
            // with dynamic naming using placeholders (%s and %d).
            FileBuffer fileBuffer = networks.createFileBuffer("file-buffer-%s");
            TransmitBuffer txBuffer = networks.createTxBuffer("transmit-buffer-%d");

            // Step 3: Open file capture and transmitter
            // Initializes a NetFileCapture for reading the PCAP file and a NetTransmit for network transmission,
            // ensuring resource cleanup with try-with-resources.
            try (NetFileCapture fileCapture = networks.openFile(filename, fileBuffer);
                    NetTransmit transmitter = networks.openTransmit(txBuffer)) {

                // Step 4: Start the transmitter
                // Activates the transmitter to process and send packets from the transmit buffer.
                transmitter.start();

                // Flag to handle the first packet's timing synchronization
                boolean firstPacket = true;

                // Step 5: Process and transmit packet segments
                // Iterates over available packet segments, copies them to the transmit buffer, synchronizes
                // the first packet's timestamp, and releases segments for transmission.
                while (fileCapture.hasRemaining()) {
                    FileSegment fileSegment = fileBuffer.take();
                    NetSegment txSegment = txBuffer.take();

                    // Copy the file segment to the transmit segment and prepare for transmission
                    txSegment.put(fileSegment)
                            .flip(); // Adjusts position and limit for NIO-style buffer handling

                    // Synchronize transmission clock and preserve inter-frame gaps for the first packet
                    if (firstPacket) {
                        firstPacket = false;

                        Packet packet = txSegment.getPacket(0); // Retrieves the first packet
                        if (packet.descriptor() instanceof TxAttributes txPacket) {
                            txPacket.setSynchronizeClockWithTimestamp(true); // Aligns clock with packet timestamp
                            txPacket.setTransmitImmediately(false); // Preserves inter-frame gaps
                        }
                    }

                    // Release the transmit segment to trigger transmission
                    txBuffer.release(txSegment);

                    // Release the file segment to free memory for the next iteration
                    fileBuffer.release(fileSegment);
                }
            } // Step 6: Close file capture and transmitter
            // Resources are automatically closed by try-with-resources, ensuring no leaks.
        }
    }
}