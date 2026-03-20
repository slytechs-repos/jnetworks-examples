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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import com.slytechs.sdk.common.util.HexBytes;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorType;
import com.slytechs.sdk.protocol.core.id.L2FrameType;

public class PacketDslMain {

	static String str = "0026622f4787001d60b301840800" // Ethernet II, Src: ASUSTekCOMPU_b3:01:84 (00:1d:60:b3:01:84), Dst: ActiontecEle_2f:47:87 (00:26:62:2f:47:87)
			+ "450000bacb5d400040062864c0a8018cae8fd5b8" // Internet Protocol Version 4, Src: 192.168.1.140, Dst: 174.143.213.184
			+ "e14e00508e501902c7529d898018002e472900000101080a0021d25f31c7ba48" // Transmission Control Protocol, Src Port: 57678, Dst Port: 80, Seq: 1, Ack: 1, Len: 134
			+ "474554202f696d616765732f6c61796f75742f6c6f676f2e706e672048545450"
			+ "2f312e300d0a557365722d4167656e743a20576765742f312e313220286c696e"
			+ "75782d676e75290d0a4163636570743a202a2f2a0d0a486f73743a207061636b"
			+ "65746c6966652e6e65740d0a436f6e6e656374696f6e3a204b6565702d416c69"
			+ "76650d0a0d0a"; // Hypertext Transfer Protocol

	/** Sample Ethernet frame: Dst MAC + Src MAC + EtherTypes (IPv4) + payload */
	static final byte[] SAMPLE_PACKET = HexBytes.parse(str);

	// @formatter:off
	static final byte[] SAMPLE_PACKET2 = {
        // Ethernet header (14 bytes)
        (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55,  // Dst MAC
        (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,  // Src MAC
        (byte) 0x08, (byte) 0x00,  // EtherTypes: IPv4
        // IPv4 header (20 bytes minimum)
        (byte) 0x45, (byte) 0x00, (byte) 0x00, (byte) 0x28,  // Version, IHL, TOS, Total Length
        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,  // ID, Flags, Fragment Offset
        (byte) 0x40, (byte) 0x06, (byte) 0x00, (byte) 0x00,  // TTL, Protocol (TCP), Checksum
        (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01,  // Src IP: 192.168.1.1
        (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x02,  // Dst IP: 192.168.1.2
        // TCP header (20 bytes)
        (byte) 0x00, (byte) 0x50, (byte) 0x1F, (byte) 0x90,  // Src Port: 80, Dst Port: 8080
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,  // Sequence Number
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,  // Ack Number
        (byte) 0x50, (byte) 0x02, (byte) 0x20, (byte) 0x00,  // Data Offset, Flags (SYN), Window
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00   // Checksum, Urgent Pointer
    };
	// @formatter:on
	/** PCAP_PACKED header values */
	static final int PACKET_LENGTH = SAMPLE_PACKET.length;
	static final int PCAP_TS_SEC = 1704067200; // 2024-01-01 00:00:00 UTC
	static final int PCAP_TS_USEC = 123456;
	static final int PCAP_CAPLEN = PACKET_LENGTH;
	static final int PCAP_WIRELEN = PACKET_LENGTH;

	static MemorySegment createPacketData(Arena arena) {
		MemorySegment seg = arena.allocate(PACKET_LENGTH, 8);
		for (int i = 0; i < SAMPLE_PACKET.length; i++) {
			seg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
		}
		return seg;
	}

	static MemorySegment createPcapHeader(Arena arena) {
		// PCAP_PACKED header:
		// ts_sec (4) + ts_usec (4) + caplen (4) + wirelen (4) = 16 bytes
		MemorySegment seg = arena.allocate(24, 8);
		seg.set(ValueLayout.JAVA_INT, 0, PCAP_TS_SEC);
		seg.set(ValueLayout.JAVA_INT, 8, PCAP_TS_USEC);
		seg.set(ValueLayout.JAVA_INT, 16, PCAP_CAPLEN);
		seg.set(ValueLayout.JAVA_INT, 20, PCAP_WIRELEN);
		return seg;
	}

	static Packet createPacket(Arena arena) {
		Packet packet = Packet.ofScopedType(DescriptorType.PCAP_PADDED);

		MemorySegment pktSeg = createPacketData(arena);
		packet.boundMemory()
				.asScopedMemory()
				.bind(pktSeg, 0, pktSeg.byteSize());

		MemorySegment dscSeg = createPcapHeader(arena);
		packet.descriptor()
				.boundMemory()
				.asScopedMemory()
				.bind(dscSeg, 0, dscSeg.byteSize());

		packet.descriptor().setL2FrameType(L2FrameType.ETHER);

		return packet;
	}

	public static void main(String[] args) {
		Packet packet = createPacket(Arena.ofAuto());

		String output = packet.toText().toString();
		System.out.println(output);
	}
}