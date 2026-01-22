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
import java.util.stream.Collectors;

import com.slytechs.sdk.common.memory.MemoryBuffer;
import com.slytechs.sdk.common.session.SessionShutdownException;
import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.NetException;
import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.channels.PacketChannelSettings;
import com.slytechs.sdk.jnetworks.concurrency.TaskContext;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.concurrency.TaskRecovery;
import com.slytechs.sdk.jnetworks.device.Port;
import com.slytechs.sdk.jnetworks.net.Capture;
import com.slytechs.sdk.jnetworks.net.Inline;
import com.slytechs.sdk.jnetworks.net.Transmit;
import com.slytechs.sdk.jnetworks.pcap.PcapBackend;
import com.slytechs.sdk.protocol.core.EtherType;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.stack.ProtocolStack;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;

/**
 * Showcase example for jNetWorks SDK.
 * 
 * <p>
 * Demonstrates three different channel use cases:
 * <ul>
 * <li>Creating a backend and channel</li>
 * <li>Setting up a capture pipeline</li>
 * <li>Setting up a inline/IDS pipeline</li>
 * <li>Setting up a transmit packet pool</li>
 * <li>Processing packets with acquire/release</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Showcase {

	public static void main(String[] args) {
		new Showcase().run();
	}

	public void run() {
		// Searches for commercial license or fallback on community license
		Net.activateLicense();

		// use DpdkBackend with DPDK capable NICs/Ports
		// use Ntapi with Napatech SmartNIC configured adapters/Ports
		try (Net net = new PcapBackend()) {

			ProtocolStack stack = new ProtocolStack(); // Enables IPF/TCP reassembly
			PacketChannelSettings settings = new PacketChannelSettings(); // Channel options

			PacketChannel capChannel = net.packetChannel("capture-channel", settings, stack);
			PacketChannel idsChannel = net.packetChannel("inline-ids-channel", settings, stack);
			PacketChannel genChannel = net.packetChannel("traffic-gen-channel", settings, stack);

			// Start capture only, on first active (with traffic) ETH port
			Capture capture = net.capture("capture-channel", "en0")
					.filter("tcp") // Pcap BPF filter
					.assignTo(capChannel) // Traffic distributed to this channel, need to fork a Task
					.apply(); // Start capture, no tx capabilities

			Inline inline = net.inline("inline-ids-channel", "en1")
					.filter("all") // Pcap BPF filter Pcap.setFilter()
					.assignTo(idsChannel) // Traffic distributed to this channel, need to fork a task
					.txEnable(true) // Default TX flags on each packet
					.txPort("en0") // Default TX port
					.txImmediately() // Do not preserve IFG
					.apply(); // Start capture + tx-queue router

			Transmit transmit = net.transmit("traffic-gen-channel")
					.ports(Port.ETHERNET.up()) // Enable TX on all ETH ports that are UP
					.assignTo(genChannel) // Will provide empty buffers for pkt gen
					.enable() // Enable TX on the selected ports
					.apply(); // Start buffers flowing and tx-queue packet router

			System.out.println("Selected port for capture: " + capture.getPort());
			System.out.println("Selected port for inline: " + inline.getPort());
			System.out.println("Selected ports for transmit: " + transmit.listPorts().stream()
					.map(Port::name)
					.collect(Collectors.joining(", ")));

			try (TaskExecutor executor = net.executor("packet-tasks")) {
				executor.onTaskException(this::handleErrors)
						.maxRestarts(3)
						.restartDelay(Duration.ofSeconds(1));

				Port en0 = net.getPort("en0");
				Port en1 = net.getPort("en1");

				// Use different fork methods to attach task to channels
				executor.fork(capChannel, this::capturedPackets)
						.fork(idsChannel, this::intrusionDetection)
						.fork(genChannel, en0, en1, this::generateTraffic) // Can pass multiple args too
						.shutdownAfter(Duration.ofMinutes(5))
						.awaitCompletion();

			} catch (Throwable e) {
				e.printStackTrace();
			}
			System.out.printf("Capture complete: %d packets%n", capture.metrics().packetsAssigned());

		} catch (NetException e) {
			e.printStackTrace();
		}
	}

	TaskRecovery handleErrors(TaskContext context, Throwable error) {
		return TaskRecovery.FAIL;
	}

	/**
	 * Transmit channels packets originate from a memory and packet pools. They are
	 * empty packets/buffers ready for transmission upon release.
	 * 
	 * @param channel transmit packet pool with empty packets
	 * @param en0     port reference so we can get its info
	 * @param en1     port reference so we can get its info
	 * @throws SessionShutdownException
	 * @throws InterruptedException
	 */
	void generateTraffic(PacketChannel channel, Port en0, Port en1) throws SessionShutdownException,
			InterruptedException {

		byte[] mac1 = en0.macAddress();
		byte[] mac2 = en1.macAddress();

		MemoryBuffer buffer = new MemoryBuffer();

		while (channel.isActive()) {
			Packet packet = channel.acquire();

			// Both buffer and packet point at the same memory segment
			buffer.bind(packet);
			buffer.put(mac1);
			buffer.put(mac2);
			buffer.putShort((short) EtherType.IPv4); // ether.type = IPv4
			// Write the next Ipv4 header...

			// Update the packet length ETH + IPv4
			packet.descriptor().setCaptureLength(14 + 20);

			// Transmit on port#1 "en1"
			packet.tx().setTxPort(en1.number());

			// Packet is transmitted on release
			channel.release(packet);
		}
	}

	/**
	 * Intrusion detection. Selectively prevent packets from transmission.
	 *
	 * @param channel the channel
	 * @throws SessionShutdownException the session shutdown exception
	 * @throws InterruptedException     the interrupted exception
	 */
	void intrusionDetection(PacketChannel channel) throws SessionShutdownException, InterruptedException {
		System.out.println("Starting packet capture...");

		Ip4 ip = new Ip4();

		while (channel.isActive()) {
			Packet packet = channel.acquire();

			// Do some IDS stuff
			if (packet.hasHeader(ip) && !ip.isDf())
				packet.tx().setTxEnabled(false); // Do not transmit, drop

			channel.release(packet);
		}

		System.out.println("Capture stopped.");
	}

	/**
	 * Process captured or inline or transmit traffic. One task is attached to each
	 * channel via TaskExecutor.fork(Channel[]).
	 * 
	 * <p>
	 * Capture tasks, acquire/release packets after processing, no TX forwarding
	 * between ports.
	 * </p>
	 * <p>
	 * Inline tasks, acquire/release packets after processing/filtering. Can
	 * override default assigned TX properties and flags on each
	 * Packet.tx():TxCapabilities to drop, or direct packets to a different TX port
	 * other than default. Can injects TS, CRCs and other data into the packet.
	 * Packet uses the memory packet which allows mbuf like memory segment chaining
	 * and injection, deletion with DPDK style mbufs with headroom/tailroom in each
	 * segment for extra space.
	 * </p>
	 * <p>
	 * Traffic tasks, acquire/release empty packets/buffers from a memory pool
	 * (Arena based in Pcap, hugepages/mempools in DPDK, NT TX stream in NTAPI)
	 * where they can generate their own custom packets. Settings Packet.tx()
	 * settings upon release, transmits the packet. Prefill option prevents the
	 * packets/buffers from being reset and they after all pool elements are first
	 * acquired/released, cycle around for linerate retransmission of prefilled
	 * packet data. Transmit component uses a LockFreePool.Fifo implementation to
	 * ensure that packets/buffers are cycled around in the order they were original
	 * acquired/released. Inline also has the prefill option.
	 * </p>
	 * 
	 * @param channel
	 * @throws SessionShutdownException
	 * @throws InterruptedException
	 */
	void capturedPackets(PacketChannel channel) throws SessionShutdownException, InterruptedException {
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