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
import com.slytechs.sdk.jnetworks.concurrency.TaskScope;
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
		Net.activateLicense();

		try (Net net = new PcapBackend()) {

			ProtocolStack stack = new ProtocolStack();
			PacketChannelSettings settings = new PacketChannelSettings();

			PacketChannel channel = net.packetChannel("hello-channel", settings, stack);

			Capture capture = net.capture("hello-capture", "en0")
					.filter("tcp")
					.assignTo(channel)
					.apply();

			try (TaskScope scope = new TaskScope(net)) {
				scope.shutdownAfter(Duration.ofSeconds(10));
				scope.fork(channel, this::processPackets);
				scope.awaitCompletion();
			}

			System.out.printf("Capture complete: %d packets%n", capture.metrics().packetsAssigned());

		} catch (NetException | InterruptedException e) {
			e.printStackTrace();
		}
	}

	void processPackets(PacketChannel channel) {
		System.out.println("Starting packet capture...");

		while (channel.isActive()) {
			try {
				Packet packet = channel.acquire();

				System.out.printf("Packet: len=%d, caplen=%d%n",
						packet.descriptor().wireLength(),
						packet.descriptor().captureLength());

				channel.release(packet);

			} catch (SessionShutdownException | InterruptedException e) {
				// Normal shutdown, exit loop
			}
		}

		System.out.println("Capture stopped.");
	}
}