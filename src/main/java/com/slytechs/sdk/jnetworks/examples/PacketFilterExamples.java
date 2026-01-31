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

import com.slytechs.sdk.jnetworks.pcap.filter.BpfFilterBuilder;
import com.slytechs.sdk.jnetworks.pcap.filter.PcapPacketFilter;
import com.slytechs.sdk.protocol.core.filter.EthernetFilter;
import com.slytechs.sdk.protocol.core.filter.Ip4Filter;
import com.slytechs.sdk.protocol.core.filter.IpSecFilter;
import com.slytechs.sdk.protocol.core.filter.MplsFilter;
import com.slytechs.sdk.protocol.core.filter.PacketFilter;
import com.slytechs.sdk.protocol.core.filter.ProtocolFilter;
import com.slytechs.sdk.protocol.core.filter.TcpFilter;
import com.slytechs.sdk.protocol.core.filter.UdpFilter;
import com.slytechs.sdk.protocol.core.filter.VlanFilter;

/**
 * Demonstrates the type-safe packet filter DSL for building backend-agnostic
 * network filters.
 * 
 * <p>
 * The {@link PacketFilter} API provides a fluent, composable way to define
 * packet filters that can target multiple backends including libpcap (BPF),
 * DPDK (rte_flow/eBPF), and Napatech (NTPL). Filters are defined once using the
 * {@link ProtocolFilter} DSL and compiled to backend-specific
 * {@link PacketFilter} implementations.
 * 
 * <h2>API Design</h2>
 * <p>
 * The filter API follows a two-phase pattern:
 * <ol>
 * <li><b>Define</b> - Use {@link PacketFilter} static factories to build a
 * {@link ProtocolFilter} DSL chain</li>
 * <li><b>Compile</b> - Use a backend-specific builder to produce a compiled
 * {@link PacketFilter}</li>
 * </ol>
 * 
 * {@snippet :
 * // Phase 1: Define filter using DSL
 * ProtocolFilter dsl = PacketFilter
 * 		.vlan(v -> v.vid(100))
 * 		.ip4()
 * 		.tcp(tcp -> tcp.port(443));
 *
 * // Phase 2: Compile to backend-specific filter
 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
 *
 * // Use compiled filter
 * String expr = filter.toExpression();
 * BpfProgram bpf = filter.toBpfProgram(pcap, snaplen, optimize);
 * }
 * 
 * <h2>Backend Support</h2>
 * <p>
 * The same DSL definition compiles to different backends:
 * <ul>
 * <li>{@link BpfFilterBuilder} → {@link PcapPacketFilter} (libpcap BPF)</li>
 * <li>{@code RteFlowBuilder} → {@code DpdkPacketFilter} (DPDK rte_flow or
 * eBPF)</li>
 * <li>{@code NtplFilterBuilder} → {@code NtapiPacketFilter} (Napatech
 * NTPL)</li>
 * </ul>
 * 
 * <h2>Integration with Capture API</h2>
 * 
 * {@snippet :
 * ProtocolFilter dsl = PacketFilter.ip4().tcp(tcp -> tcp.port(443));
 *
 * Capture capture = net.capture("main", "eth0")
 * 		.filter(dsl)
 * 		.assignTo(channels)
 * 		.apply();
 *
 * // Retrieve compiled filter from capture
 * PacketFilter filter = capture.getFilter();
 * }
 * 
 * <h2>Debug Methods</h2>
 * <p>
 * The {@link ProtocolFilter#onExpression} and
 * {@link ProtocolFilter#onExpressionAssert} methods are provided for
 * development and testing purposes only. These methods intercept the expression
 * during the build phase and should not be used in production code. Use
 * {@link PacketFilter#toExpression()} on the compiled filter instead.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc
 * @see PacketFilter
 * @see ProtocolFilter
 * @see BpfFilterBuilder
 */
public class PacketFilterExamples {

	/** Expected output for assertion validation. */
	static String expectedOutput;

	/** DSL filter chain before compilation. */
	static ProtocolFilter dsl;

	/**
	 * Demonstrates basic VLAN filtering by VLAN ID.
	 * 
	 * <p>
	 * Creates a filter matching packets with a specific VLAN tag. The
	 * {@link VlanFilter} provides access to all 802.1Q fields including VID, PCP,
	 * and DEI.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter.vlan(v -> v.vid(111));
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "vlan and vlan 111"
	 * }
	 * 
	 * @see VlanFilter
	 */
	static void vlan() {
		System.out.println("-- vlan -- ");

		expectedOutput = "vlan and vlan 111";
		dsl = PacketFilter
				.vlan(v -> v.vid(111))
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates a TLS/HTTPS traffic filter using protocol composition.
	 * 
	 * <p>
	 * Combines Ethernet type filtering with OR logic for protocol alternatives,
	 * then filters by TCP destination port. This pattern is common for capturing
	 * encrypted web traffic.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter
	 * 		.ethernet(eth -> eth.type(0x800))
	 * 		.anyOf(
	 * 				Ip4Filter.protocol(6),   // TCP
	 * 				Ip4Filter.protocol(17))  // UDP
	 * 		.tcp(tcp -> tcp.dstPort(443));
	 *
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "ether and ether proto 0x0800 and 
	 * //     (ip proto 6 or ip proto 17) and tcp and tcp dst port 443"
	 * }
	 * 
	 * @see EthernetFilter
	 * @see Ip4Filter
	 * @see TcpFilter
	 */
	static void tls() {
		System.out.println("-- tls -- ");

		expectedOutput = "ether and ether proto 0x0800 and (ip proto 6 or ip proto 17) and tcp and tcp dst port 443";
		dsl = PacketFilter
				.ethernet(eth -> eth.type(0x800))
				.anyOf(
						Ip4Filter.protocol(6),
						Ip4Filter.protocol(17))
				.tcp(tcp -> tcp.dstPort(443))
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates UDP filtering with bidirectional port matching.
	 * 
	 * <p>
	 * The {@code port()} method on {@link UdpFilter} creates an OR group matching
	 * either source or destination port, which is the common pattern for capturing
	 * both sides of a conversation.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter.ip4().udp(udp -> udp.port(53));
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "ip and udp and (udp src port 53 or udp dst port 53)"
	 * }
	 * 
	 * @see UdpFilter
	 */
	static void udp() {
		System.out.println("-- udp -- ");

		expectedOutput = "ip and udp and (udp src port 53 or udp dst port 53)";
		dsl = PacketFilter
				.ip4()
				.udp(udp -> udp.port(53))
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates basic IPSec ESP protocol filtering.
	 * 
	 * <p>
	 * Matches Encapsulating Security Payload (ESP) packets, IP protocol 50. This is
	 * the basic form without SPI filtering.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter.ip4().esp();
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "ip and ip proto 50"
	 * }
	 * 
	 * @see IpSecFilter
	 */
	static void esp() {
		System.out.println("-- esp -- ");

		expectedOutput = "ip and ip proto 50";
		dsl = PacketFilter
				.ip4()
				.esp()
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates IPSec ESP filtering with Security Parameter Index (SPI).
	 * 
	 * <p>
	 * Filters ESP traffic by specific SPI value, useful for isolating individual
	 * IPSec tunnels or security associations.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter.ip4().esp(ipsec -> ipsec.espSpi(0x12345678));
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "ip and ip proto 50 and ip[20:4] == 0x12345678"
	 * }
	 * 
	 * @see IpSecFilter
	 */
	static void ipSecEsp() {
		System.out.println("-- ipSecEsp -- ");

		expectedOutput = "ip and ip proto 50 and ip[20:4] == 0x12345678";
		dsl = PacketFilter
				.ip4()
				.esp(ipsec -> ipsec.espSpi(0x12345678))
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates IPSec Authentication Header (AH) filtering with SPI.
	 * 
	 * <p>
	 * Filters AH traffic (IP protocol 51) by specific SPI value. AH provides data
	 * integrity and authentication without encryption.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter.ip4().ah(ipsec -> ipsec.ahSpi(0xDEADBEEF));
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "ip and ip proto 51 and ip[24:4] == 0xdeadbeef"
	 * }
	 * 
	 * @see IpSecFilter
	 */
	static void ah() {
		System.out.println("-- ah -- ");

		expectedOutput = "ip and ip proto 51 and ip[24:4] == 0xdeadbeef";
		dsl = PacketFilter
				.ip4()
				.ah(ipsec -> ipsec.ahSpi(0xDEADBEEF))
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates VLAN and IP version filtering with OR groups.
	 * 
	 * <p>
	 * Uses nested {@code anyOf()} to match multiple VLAN IDs and multiple IP
	 * versions. This pattern is useful for multi-tenant or dual-stack environments.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter
	 * 		.anyOf(VlanFilter.vid(1111), VlanFilter.vid(2222))
	 * 		.anyOf(PacketFilter.ip4(), PacketFilter.ip6());
	 *
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "(vlan 1111 or vlan 2222) and (ip or ip6)"
	 * }
	 * 
	 * @see VlanFilter
	 */
	static void vlanIp() {
		System.out.println("-- vlanIp -- ");

		expectedOutput = "(vlan 1111 or vlan 2222) and (ip or ip6)";
		dsl = PacketFilter
				.anyOf(
						VlanFilter.vid(1111),
						VlanFilter.vid(2222))
				.anyOf(
						PacketFilter.ip4(),
						PacketFilter.ip6())
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates MPLS filtering for both BPF and DPDK backends.
	 * 
	 * <p>
	 * Shows the same DSL compiled to different backends. MPLS filtering includes
	 * label, traffic class, bottom-of-stack flag, and TTL fields.
	 * 
	 * {@snippet :
	 * // Define once
	 * ProtocolFilter dsl = PacketFilter.mpls(mpls -> mpls.label(100)).ip4();
	 *
	 * // Compile for BPF
	 * PcapPacketFilter bpfFilter = new BpfFilterBuilder().build(dsl);
	 * // bpfFilter.toExpression(): "mpls and mpls label 100 and ip"
	 *
	 * // Compile for DPDK rte_flow
	 * DpdkPacketFilter dpdkFilter = new RteFlowBuilder().build(dsl);
	 * // dpdkFilter.toExpression(): struct rte_flow_item pattern[] = { MPLS, IPV4, END }
	 * }
	 * 
	 * @see MplsFilter
	 */
	static void mpls() {
		System.out.println("-- mpls -- ");

		// BPF backend
		expectedOutput = "mpls and mpls label 100 and ip";
		dsl = PacketFilter
				.mpls(mpls -> mpls.label(100))
				.ip4()
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter bpfFilter = new BpfFilterBuilder().build(dsl);
		System.out.println(bpfFilter.toExpression());

		// DPDK rte_flow backend
		dsl = PacketFilter
				.mpls(mpls -> mpls.label(100).bottomOfStack())
				.ip4();

		/*
		 * Presented for demo purposes only
		 */
//        PacketFilter dpdkFilter = new RteFlowBuilder().build(dsl);
//        System.out.println(dpdkFilter.toExpression());
	}

	/**
	 * Demonstrates host, network, port range, and packet length filtering.
	 * 
	 * <p>
	 * These primitives provide high-level filtering without specifying protocol
	 * details:
	 * <ul>
	 * <li>{@code host()} - Matches source OR destination IP</li>
	 * <li>{@code srcNet()/dstNet()} - CIDR subnet filtering</li>
	 * <li>{@code portRange()} - Matches TCP or UDP port ranges</li>
	 * <li>{@code lengthGreater()} - Packet size filtering</li>
	 * <li>{@code multicast()} - Multicast traffic only</li>
	 * </ul>
	 * 
	 * {@snippet :
	 * // Host filtering
	 * ProtocolFilter dsl = PacketFilter.host("10.0.0.1").tcp();
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "host 10.0.0.1 and tcp"
	 *
	 * // Subnet filtering
	 * dsl = PacketFilter.srcNet("192.168.0.0/16").dstNet("10.0.0.0/8");
	 * filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "src net 192.168.0.0/16 and dst net 10.0.0.0/8"
	 * }
	 */
	static void hostNet() {
		System.out.println("-- hostNet -- ");

		// Filter by host
		expectedOutput = "host 10.0.0.1 and tcp";
		dsl = PacketFilter.host("10.0.0.1")
				.tcp()
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());

		// Filter by subnet
		expectedOutput = "src net 192.168.0.0/16 and dst net 10.0.0.0/8";
		dsl = PacketFilter.srcNet("192.168.0.0/16")
				.dstNet("10.0.0.0/8")
				.onExpressionAssert(expectedOutput::equals);

		filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());

		// Port range
		expectedOutput = "ip and portrange 8000-9000";
		dsl = PacketFilter.ip4()
				.portRange(8000, 9000)
				.onExpressionAssert(expectedOutput::equals);

		filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());

		// Large packets only
		expectedOutput = "ip and greater 1000";
		dsl = PacketFilter.ip4()
				.lengthGreater(1000)
				.onExpressionAssert(expectedOutput::equals);

		filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());

		// Multicast traffic
		expectedOutput = "ip and multicast and udp";
		dsl = PacketFilter.ip4()
				.multicast()
				.udp()
				.onExpressionAssert(expectedOutput::equals);

		filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Demonstrates a real-world enterprise filter combining VLANs with IPSec.
	 * 
	 * <p>
	 * This example shows a typical enterprise or government network filter that
	 * captures IPSec traffic from specific VLANs. Combines OR groups with protocol
	 * chaining and subnet filtering.
	 * 
	 * {@snippet :
	 * ProtocolFilter dsl = PacketFilter
	 * 		.anyOf(VlanFilter.vid(3333), VlanFilter.vid(4444))
	 * 		.ip4()
	 * 		.esp()
	 * 		.srcNet("10.0.0.0/8");
	 *
	 * PcapPacketFilter filter = new BpfFilterBuilder().build(dsl);
	 * // filter.toExpression(): "(vlan 3333 or vlan 4444) and ip and ip proto 50
	 * //     and src net 10.0.0.0/8"
	 * }
	 * 
	 * @see VlanFilter
	 * @see IpSecFilter
	 */
	static void vlans() {
		System.out.println("-- vlans -- ");

		// Multiple VLANs with IP version filtering
		expectedOutput = "(vlan 3333 or vlan 4444) and (ip or ip6)";
		dsl = PacketFilter.anyOf(
				VlanFilter.vid(3333),
				VlanFilter.vid(4444))
				.anyOf(
						PacketFilter.ip4(),
						PacketFilter.ip6())
				.onExpressionAssert(expectedOutput::equals);

		PacketFilter filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());

		// VLANs with IPSec and subnet
		expectedOutput = "(vlan 3333 or vlan 4444) and ip and ip proto 50 and src net 10.0.0.0/8";
		dsl = PacketFilter.anyOf(
				VlanFilter.vid(3333),
				VlanFilter.vid(4444))
				.ip4()
				.esp()
				.srcNet("10.0.0.0/8")
				.onExpressionAssert(expectedOutput::equals);

		filter = new BpfFilterBuilder().build(dsl);
		System.out.println(filter.toExpression());
	}

	/**
	 * Runs all filter examples with output validation.
	 * 
	 * <p>
	 * Each example validates its output against expected values using
	 * {@code onExpressionAssert()}. Any mismatch throws
	 * {@link IllegalStateException}.
	 * 
	 * <p>
	 * <b>Note:</b> The {@code onExpression()} and {@code onExpressionAssert()}
	 * methods on {@link ProtocolFilter} are for development and testing only. In
	 * production code, use {@link PacketFilter#toExpression()} on the compiled
	 * filter returned by the builder.
	 *
	 * @param args command line arguments (unused)
	 */
	public static void main(String[] args) {
		vlan();
		tls();
		udp();
		esp();
		ipSecEsp();
		ah();
		vlanIp();
		mpls();
		hostNet();
		vlans();

		System.out.println("\nAll filter examples passed.");
	}
}