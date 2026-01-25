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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.slytechs.sdk.common.memory.MemoryBuffer;
import com.slytechs.sdk.common.session.SessionShutdownException;
import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.NetException;
import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.channels.ProtocolChannel;
import com.slytechs.sdk.jnetworks.channels.TokenChannel;
import com.slytechs.sdk.jnetworks.concurrency.TaskContext;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.concurrency.TaskRecovery;
import com.slytechs.sdk.jnetworks.device.Port;
import com.slytechs.sdk.jnetworks.device.PortFilter;
import com.slytechs.sdk.jnetworks.net.Capture;
import com.slytechs.sdk.jnetworks.net.Inline;
import com.slytechs.sdk.jnetworks.net.Transmit;
import com.slytechs.sdk.jnetworks.pcap.PcapBackend;
import com.slytechs.sdk.protocol.core.EtherType;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.flow.FlowKey;
import com.slytechs.sdk.protocol.core.stack.ProtocolStack;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.TcpSegment;
import com.slytechs.sdk.protocol.tcpip.tcp.TcpStream;
import com.slytechs.sdk.protocol.tcpip.tcp.TcpToken;

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

	/**
	 * Our showcase state stub. Implement to handle real use-cases.
	 */
	interface State {
		static State createFromStream(FlowKey flowKey) {
			throw new UnsupportedOperationException("Need to implement real state here");
		}

		void analyzeCongestion(TcpStream stream);

		void detectAnomaly(TcpStream stream, String anomaly);

		void detectCongestion(TcpStream stream);

		void detectLoss(TcpStream stream);

		void handleConnectionEnd(TcpStream stream);

		void handleConnectionReset(TcpStream stream);

		void handleConnectionStart(TcpStream stream);

		void markForEviction();

		void monitorPerformance(TcpStream stream);

	}

	public static void main(String[] args) {
		new Showcase().run();
	}

	private final Map<FlowKey, State> stateMap = new HashMap<>();

	/**
	 * Analyze TCP token streams. Tokens are lightweight analysis objects. There are
	 * many different types of generic analysis tokens (boundary start or end, etc)
	 * and specific like the one here for TCP stream analysis. This is also a
	 * perfect point to forward the tokens to a ML/AI for training or inference.
	 * 
	 * <p>
	 * Tokens are emmitted by the ProtocolStack during processing. Some tokens are
	 * emmitted directly during protocol processing and others with additional
	 * analyzers. ProtocolStack also has additional Analyzers, if enabled, which can
	 * be attached for full analysis, during the processing stage instead of after
	 * the reassembly phase like here.
	 * </p>
	 * <p>
	 * Tokens do not hold references to full frames, only IDs/FlowKeys to cached
	 * state data which has to be looked up or retrieved. However they do store
	 * frame numbers of the packet that the token was generated for. If the packet
	 * data is read from storage, the frames can be retrieved on demand or extracted
	 * from additional cache. A common use-case is for frame numbers to over lap
	 * with packet data already crunched and sent to an application, with direct
	 * correlation of of the token event. For example, flow-start/flow-end frame
	 * numbers, in a GUI based application will include or highlight the matching
	 * starting frame of a flow in different color to indicate the flow start based
	 * on the token data and the previous analysis already performed.
	 * </p>
	 * 
	 * @param channel
	 * @throws SessionShutdownException
	 * @throws InterruptedException
	 */
	void analyzeTcpTokens(TokenChannel<TcpToken> channel) throws SessionShutdownException, InterruptedException {

		while (channel.isActive()) {
			TcpToken token = channel.acquire();
			TcpStream stream = token.tcpStream();
			long frameno = token.frameNumber();

			State state = stateMap.get(stream.flowKey());

			switch (token.tokenType()) {
			case STREAM_SYN -> state.handleConnectionStart(stream);
			case STREAM_FIN -> {
				state.handleConnectionEnd(stream);
				state.markForEviction(); // Flag for cleanup
			}
			case STREAM_TIMEOUT -> stateMap.remove(stream.flowKey()); // Immediate removal
			case SEGMENT_OUT_OF_ORDER -> state.detectAnomaly(stream, "OOO");
			case WINDOW_RESIZE -> state.monitorPerformance(stream);
			case STREAM_RST -> state.handleConnectionReset(stream);
			case RETRANSMIT -> state.detectLoss(stream);
			case FAST_RETRANSMIT -> state.detectCongestion(stream);
			case DUPLICATE_ACK -> state.analyzeCongestion(stream);

			// Per-channel disable - not interested in this token type - Automatic token
			// pruning
			default -> channel.disable(token.tokenType());
			}

			channel.release(token);
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

	/**
	 * Transmit channels packets originate from a memory and packet pools. They are
	 * empty packets/buffers ready for transmission upon release.
	 * 
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

			// Override transmit on port "en1"
			packet.tx().setTxPort(en1.number());

			// Packet is transmitted on release
			channel.release(packet);
		}
	}

	TaskRecovery handleErrors(TaskContext context, Throwable error) {

		// Find out what happened and to which task
		// Perform error recovery
		// Return a recovery instruction
		// one of: FAIL, RESTART, SHUTDOWN_GROUP, RESTART_DELAYED

		if (context.restartCount() == 0) // Attempt recovery only once
			return TaskRecovery.RESTART_DELAYED;

		return TaskRecovery.SHUTDOWN_GROUP;
	}

	/**
	 * Intrusion detection. Selectively prevent packets from transmission.
	 * 
	 * <p>
	 * Inline tasks, acquire/release packets after processing/filtering. Can
	 * override default assigned TX properties and flags on each
	 * Packet.tx():TxCapabilities to drop, or direct packets to a different TX port
	 * other than default. Can injects TS, CRCs and other data into the packet.
	 * Packet uses the memory packet which allows mbuf like memory segment chaining
	 * and injection, deletion with DPDK style mbufs with headroom/tailroom in each
	 * segment for extra space.
	 * </p>
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
	 * Process reassembled TCP stream segments. We could have chosen to process
	 * TcpStream objects instead of TcpSegment as well.
	 * 
	 * TcpSegments are re-ordered, buffered and no holes present.
	 * 
	 * @param channel
	 * @throws SessionShutdownException
	 * @throws InterruptedException
	 */
	void processTcpStreams(ProtocolChannel<TcpSegment> channel) throws SessionShutdownException, InterruptedException {

		while (channel.isActive()) {
			TcpSegment segment = channel.acquire();
			TcpStream stream = segment.tcpStream();

			// Create state on first segment of flow
			if (!stateMap.containsKey(stream.flowKey()))
				stateMap.computeIfAbsent(stream.flowKey(), State::createFromStream);

			if (stream.isClient()) {
				System.out.println("Received client request");
			} else {
				System.out.println("Received server response");
			}

			channel.release(segment);
		}
	}

	/**
	 * Comprehensive and somewhat complex showcase of various use-cases for traffic
	 * capture, inline retransmission, traffic generation and specific protocol
	 * handling and analysis. Single use applications do not neccessarily need to
	 * utilize all of these features all at once.
	 * 
	 * <p>
	 * See HelloCapture example for a simpler usage example.
	 * </p>
	 * 
	 * <p>
	 * This example demonstrates the common functionality available across all 3
	 * backends/implementations (PCAP, DPDK and Napatech NTAPI software). Backend
	 * specific overrides and hardware offloads are fully utilized and available for
	 * user configuration.
	 * </p>
	 * <p>
	 * For other backends, the setup pattern is as follows:
	 * {@snippet :
	 * try (Pcap pcap = new PcapBackend(settings)) {}
	 * try (Dpdk dpdk = new DpdkBackend(settings)) {}
	 * try (Ntapi ntapi = new NtapiBackend(settings)) {}
	 * try (Net net = new DpdkBackend(settings)) {} // For generic functionality using DPDK software
	 * }
	 * With each pattern, you work with specific subclass which provides additional
	 * methods and functionality which may not be portable to other backends.
	 * </p>
	 * <p>
	 * For example:
	 * {@snippet :
	 * try (Dpdk dpdk = new DpdkBackend()) {
	 * 	PacketChannel[] channels = dpdk.packetChannels("example", 4); // Create 4 packet channels
	 *  	DpdkCapture capture = dpdk.capture("my capture", PortFilter.ETHERNET.active().first())
	 *  		.assignTo(channels) // Create 4 rx-queues, one for each channel
	 *  		.lcore(4) // LCORE 0 through 3 affinity locked, when forked will use a DPDK assigned LCORE threads
	 *  		.apply(); // Applies a single rx-queue on first active (with traffic) capable DPDK port.
	 * }
	 * }
	 * </p>
	 */
	public void run() {
		// Searches for commercial license or fallback on community license
		Net.activateLicense();

		// use DpdkBackend with DPDK capable NICs/Ports
		// use Ntapi with Napatech SmartNIC configured adapters/Ports
		try (Net net = new PcapBackend()) {

			// Packet channels will receive packets (captured, dissected, analyzed or empty
			// for transmit)
			PacketChannel[] capChannels = net.packetChannels("capture-channel", 4);
			PacketChannel[] idsChannels = net.packetChannels("inline-ids-channel", 8);
			PacketChannel[] genChannels = net.packetChannels("traffic-gen-channel", 4);

			// The channels that will receive reassembled TCP segments
			ProtocolChannel<TcpSegment>[] tcpChannels = net.protocolChannels("tcp-channel", 15, TcpSegment.class);

			// Tokens are lightweight, stateless analysis objects (16+ bytes). Many token
			// types available.
			TokenChannel<TcpToken> tcpTokens = net.tokenChannel("analysis-tokens", TcpToken.class);

			// Start capture only, on ethernet port
			Capture capture = net.capture("udp-capture-channel", "en0")
					.filter("udp") // Pcap BPF filter
					.assignTo(capChannels) // Traffic distributed to these channels, need to fork multiple tasks
					.apply(); // Start capture, no tx capabilities

			// Start inline capture-forward-transmit, en1 -> en0
			Inline inline = net.inline("inline-ids-channel", "en1")
					.filter("all") // Pcap BPF filter Pcap.setFilter()
					.assignTo(idsChannels) // Traffic distributed to these channels, need to fork multiple tasks
					.txEnable(true) // Default TX flags on each packet
					.txPorts("en0") // Default TX port
					.txImmediately() // Do not preserve IFG
					.apply(); // Start capture + tx-queue router

			// Enable TX on all ETH ports that are UP and generate custom traffic
			Transmit transmit = net.transmit("traffic-gen-channel", PortFilter.ETHERNET.up())
					.assignTo(genChannels) // Will provide empty buffers for pkt gen
					.txEnable(true) // Default TX flags on each packet
					.txPort("en0") // Default TX port, can override in task worker on per-packet basis
					.txImmediately() // Do not preserve IFG
					.apply(); // Start buffers flowing and tx-queue packet router

			// Demonstrate the protocol stack usage
			ProtocolStack stack = new ProtocolStack() // Enables IPF/TCP reassembly
					.enableIpReassembly() // Shortcut or configure protocol fully with
											// ProtocolStack.getProtocol(IpProtocol.class)
					.enableTcpReassembly(); // Shortcut for common use case

			// Assign TCP traffic for IP/TCP processing
			Capture tcpReassembled = net.capture("tcp-reassembled-capture", "en0")
					.filter("tcp") // limit to TCP traffic only
					.assignTo(tcpChannels) // assign to protocol channel, will receive protocol objects not packets
					.assignTo(tcpTokens) // Tokens sent to this token channel
					.protocol(stack) // Use this protocol stack for protocol level processing
					.apply();

			System.out.println("Selected port for capture: " + capture.getPort());
			System.out.println("Selected port for inline: " + inline.getPort());
			System.out.println("Selected ports for transmit: " + transmit.listPorts().stream()
					.map(Port::name)
					.collect(Collectors.joining(", ")));
			System.out.println("Selected port for tcp stream reassembly: " + tcpReassembled.getPort());

			// Manage and fork our task workers try-with-resources for proper shutdown/error
			// handling
			try (TaskExecutor executor = net.executor("packet-tasks")) {

				// How to handle errors if not handled inside the task worker, or can use
				// defaults
				executor.onTaskException(this::handleErrors)
						.maxRestarts(3)
						.restartDelay(Duration.ofSeconds(1));

				// Get some port information for our traffic generator
				Port en0 = net.getPort("en0");
				Port en1 = net.getPort("en1");

				// Use different fork methods to attach task workers to channels
				executor.fork(capChannels, this::capturedPackets) // 4 workers
						.fork(idsChannels, this::intrusionDetection) // 8 workers
						.fork(genChannels, en0, en1, this::generateTraffic) // Can pass multiple args too, 4 workers
						.fork(tcpChannels, this::processTcpStreams) // 15 workers
						.fork(tcpTokens, this::analyzeTcpTokens) // 1 worker
						.shutdownAfter(Duration.ofMinutes(5)) // Shutdown the group in 5 minutes
						.awaitCompletion(); // Wait for this task group to shutdown, 32 workers

				// Can have sub-groups executor.group("new group").fork()...
				// Workers can be affinity locked to DPDK LCORE threads

			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			System.out.printf("Capture complete: %d packets%n", capture.metrics().packetsAssigned());

		} catch (NetException e) {
			e.printStackTrace();
		}
	}
}