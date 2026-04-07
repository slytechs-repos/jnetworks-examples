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

import java.io.IOException;
import java.nio.file.Path;

import com.slytechs.sdk.jnetworks.channels.PacketBuffer;
import com.slytechs.sdk.jnetworks.channels.PacketBufferMetrics;
import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.file.pcap.PcapFile;
import com.slytechs.sdk.jnetworks.net.PacketMixer;
import com.slytechs.sdk.jnetworks.net.PacketMixer.PacketMixKey;
import com.slytechs.sdk.jnetworks.net.PacketMixerMetrics;
import com.slytechs.sdk.jnetworks.storage.Replay;
import com.slytechs.sdk.jnetworks.storage.Storage;
import com.slytechs.sdk.jnetworks.storage.StorageWriterMetrics;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.filter.PacketFilter;

/**
 * Demonstrates parallel pipeline replay with merge and high-throughput file
 * write.
 *
 * <p>
 * Workers process packets in parallel across multiple channels. A
 * {@link PacketMixer} collects the released packets from all channels,
 * re-orders them by arrival timestamp, and delivers pre-formatted EPB segments
 * to a {@link PacketBuffer}. A dedicated writer thread calls
 * {@link PcapFile#drainPackets} to flush segments to disk in bulk — no
 * per-packet formatting overhead on the write path.
 * </p>
 *
 * <h2>File setup</h2>
 * <p>
 * The output file is created and its structural blocks (SHB, IDBs) are written
 * on the calling thread before the executor starts. {@code drainPackets} is a
 * pure drain loop — all setup must be done before handing off to the executor.
 * The IDBs mirror the source file's Interface Descriptor Blocks so the output
 * is a valid PCAPNG file describing the same capture interfaces.
 * </p>
 *
 * <h2>Metrics</h2>
 * <p>
 * Every pipeline stage reports its own metrics independently after the executor
 * completes. {@link StorageWriterMetrics#packetsReencoded()} should always be
 * zero — a non-zero value means the mixer's
 * {@link com.slytechs.sdk.jnetworks.storage.spi.PacketLayout} does not match
 * the output format and the bulk write path is not active.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class FileReplayWriteExample {

	public static void main(String[] args) throws IOException, InterruptedException {
		new FileReplayWriteExample().run();
	}

	void run() throws IOException, InterruptedException {
		try (Storage storage = Storage.open(Path.of("/captures/input.pcapng"));
				PcapFile out = PcapFile.createNg(Path.of("/captures/output.pcapng"))) {

			// File header blocks written on calling thread before executor starts.
			// SHB is written by createNg(); IDBs mirror the source interfaces.
			out.writer().writeInterfaceBlocks(storage.portGroup());

			int cpus = Runtime.getRuntime().availableProcessors();
			PacketChannel[] channels = storage.packetChannels("ch-%d", cpus);
			PacketBuffer fileBuffer = storage.packetBuffer("file-buf");

			Replay replay = storage.replay("replay", storage.portGroup())
					.filter(PacketFilter.ip4())
					.assignTo(channels)
					.apply();

			PacketMixer merger = storage.mixPackets("merger", channels)
					.assignTo(fileBuffer)
					.usingKey(PacketMixKey.ARRIVAL_TIMESTAMP)
					.apply();

			try (TaskExecutor exec = storage.executor("exec")) {
				exec.forkAndExecute(merger)
						.fork(fileBuffer, out::drainPackets)
						.awaitCompletion();
			}

			// Metrics snapshots — captured after executor completes, before close
			PacketBufferMetrics bufMetrics = fileBuffer.metrics();
			PacketMixerMetrics mixMetrics = merger.metrics();
			StorageWriterMetrics writerMetrics = out.writer().metrics();

			System.out.printf("Replay:%n");
			System.out.printf("  Dispatched:        %,d packets%n", replay.packetsDispatched());
			System.out.printf("  Filtered:          %,d packets%n", replay.packetsFiltered());
			System.out.printf("  Dropped:           %,d packets%n", replay.packetsDropped());

			System.out.printf("Mixer:%n");
			System.out.printf("  Ordered:           %,d packets%n", mixMetrics.packetsOrdered());
			System.out.printf("  Dropped:           %,d packets%n", mixMetrics.packetsDropped());
			System.out.printf("  Reorder HWM:       %d slots%n", mixMetrics.reorderBufferHighWater());

			System.out.printf("Buffer:%n");
			System.out.printf("  Segments acquired: %,d%n", bufMetrics.segmentsAcquired());
			System.out.printf("  Partial segments:  %,d%n", bufMetrics.segmentsPartial());
			System.out.printf("  Pool exhausted:    %,d%n", bufMetrics.noSegmentAvailable());

			System.out.printf("Writer:%n");
			System.out.printf("  Packets written:   %,d%n", writerMetrics.packetsWritten());
			System.out.printf("  Bytes written:     %,d%n", writerMetrics.bytesWritten());
			System.out.printf("  Re-encoded:        %,d%n", writerMetrics.packetsReencoded());
			// packetsReencoded should always be 0 — non-zero = layout mismatch,
			// bulk write path not active
		}
		// both storage and out are closed here via try-with-resources
	}

	void processPackets(PacketChannel ch) throws InterruptedException {
		while (ch.isActive()) {
			Packet pkt = ch.acquire();
			analyzePacket(pkt);
			ch.release(pkt);
		}
	}

	void analyzePacket(Packet pkt) {
		// protocol analysis
	}
}