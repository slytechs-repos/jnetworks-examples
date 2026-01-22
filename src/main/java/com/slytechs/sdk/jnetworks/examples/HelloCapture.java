/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetworks.examples;

import java.time.Duration;

import com.slytechs.sdk.common.session.SessionShutdownException;
import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.NetException;
import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.channels.PacketChannelSettings;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.net.Capture;
import com.slytechs.sdk.jnetworks.pcap.PcapBackend;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.stack.ProtocolStack;

/**
 * Hello World example for jNetWorks SDK.
 * 
 * <p>
 * Demonstrates basic packet capture using the channel API:
 * <ul>
 * <li>Creating a backend and channel</li>
 * <li>Setting up a capture pipeline</li>
 * <li>Processing packets with acquire/release</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class HelloCapture {

	public static void main(String[] args) {
		new HelloCapture().run();
	}

	public void run() {
		// Searches for commercial license or fallback on community license
		Net.activateLicense();

		// use DpdkBackend with DPDK capable NICs/Ports
		// use NtapiBackend with Napatech SmartNIC configured adapters/Ports
		try (Net net = new PcapBackend()) {

			ProtocolStack stack = new ProtocolStack(); // Enables IPF/TCP reassembly
			PacketChannelSettings settings = new PacketChannelSettings(); // Channel options

			PacketChannel channel = net.packetChannel("hello-channel", settings, stack);

			// Start capture only, on first active (with traffic) ETH port
			Capture capture = net.capture("hello-capture", "en0")
					.filter("tcp") // Pcap BPF filter
					.assignTo(channel) // Traffic distributed to this channel, need to fork a Task
					.apply(); // Start capture, no tx capabilities

			System.out.println("Selected port for capture: " + capture.getPort());

			try (TaskExecutor executor = net.executor("packet-task")) {
				executor.fork(channel, this::processPackets)
						.shutdownAfter(Duration.ofSeconds(10))
						.awaitCompletion();

			} catch (Throwable e) {
				e.printStackTrace();
			}
			
			System.out.printf("Capture complete: %d packets%n", capture.metrics().packetsAssigned());

		} catch (NetException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Process captured or inline or transmit traffic. One task is attached to each
	 * channel via TaskExecutor.fork(Channel[]).
	 * 
	 * <p>
	 * Capture tasks, acquire/release packets after processing, no TX forwarding
	 * between ports.
	 * </p>
	 * 
	 * @param channel
	 * @throws SessionShutdownException
	 * @throws InterruptedException
	 */
	void processPackets(PacketChannel channel) throws SessionShutdownException, InterruptedException {
		System.out.println("Starting packet capture...");

		long count = 0;

		// Will turn to false when task or net session is shutdown.
		while (channel.isActive()) {
			Packet packet = channel.acquire(); // Acquire blocks with interrupt

			// Optionally can persist packets either from Arena or pool
			// Packet.persist(), Packet.copy(), Packet.persistTo(pool), Packet.copyTo(pool)

			count++;
			System.out.printf("Packet #%d: len=%,-6d, ts=%s%n",
					count,
					packet.captureLength(),
					packet.timestampInfo());

			channel.release(packet); // Must release

		}

		System.out.println("Capture stopped.");
	}
}