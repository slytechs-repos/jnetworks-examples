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
import java.net.URI;
import java.nio.file.Path;

import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.storage.Replay;
import com.slytechs.sdk.jnetworks.storage.Storage;
import com.slytechs.sdk.jnetworks.storage.Volume;
import com.slytechs.sdk.jnetworks.storage.VolumeCredentials;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.filter.PacketFilter;

/**
 * Demonstrates parallel pipeline replay from a capture file.
 *
 * <p>
 * Packets are distributed across multiple channels and processed in parallel
 * by dedicated worker threads — exactly as in a live capture pipeline. Worker
 * code requires no changes whether packets come from a NIC or a file.
 * </p>
 *
 * <p>
 * Each Interface Descriptor Block in the file is mapped to a
 * {@link com.slytechs.sdk.jnetworks.device.VirtualPort}. Packets are stamped
 * with the corresponding virtual port index and processed through the same
 * all-software queue pipeline (protocol dissection, timestamp normalisation,
 * token generation) as a live capture.
 * </p>
 *
 * <p>
 * Two patterns are shown: direct file open via {@link Storage} static factory,
 * and explicit {@link Volume} mount for remote backends or when multiple files
 * from the same location are processed in sequence.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class FileReplayExample {

	public static void main(String[] args) throws IOException, InterruptedException {
		FileReplayExample ex = new FileReplayExample();
		ex.replayLocal();
		ex.replayViaVolume();
	}

	/**
	 * Pipeline replay from a local file — direct Storage open.
	 * @throws InterruptedException 
	 */
	void replayLocal() throws IOException, InterruptedException {
		try (Storage storage = Storage.open(Path.of("/captures/input.pcapng"))) {

			int cpus = Runtime.getRuntime().availableProcessors();
			PacketChannel[] channels = storage.packetChannels("ch-%d", cpus);

			Replay replay = storage.replay("replay", storage.portGroup())
					.filter(PacketFilter.tcp())
					.assignTo(channels)
					.apply();

			try (TaskExecutor exec = storage.executor("exec")) {
				exec.fork(channels, this::processPackets)
						.awaitCompletion();
			}

			printReplayMetrics(replay);
		}
	}

	/**
	 * Pipeline replay from a remote backend via explicit Volume.
	 *
	 * The volume connection is established once. Each openFile call reuses it
	 * without re-authenticating. Replace the URI and credentials to target
	 * S3, GCS, Azure Blob, or any other registered VolumeProvider.
	 * @throws InterruptedException 
	 */
	void replayViaVolume() throws IOException, InterruptedException {
		VolumeCredentials creds = VolumeCredentials.fromEnv();

		try (Volume vol = Volume.mount(
				URI.create("s3://my-bucket/captures"), creds)) {

			try (Storage storage = vol.openFile("capture-2026-04.pcapng")) {

				int cpus = Runtime.getRuntime().availableProcessors();
				PacketChannel[] channels = storage.packetChannels("ch-%d", cpus);

				Replay replay = storage.replay("replay", storage.portGroup())
						.filter(PacketFilter.ip4())
						.assignTo(channels)
						.apply();

				try (TaskExecutor exec = storage.executor("exec")) {
					exec.fork(channels, this::processPackets)
							.awaitCompletion();
				}

				printReplayMetrics(replay);
			}
		}
	}

	void processPackets(PacketChannel ch) throws InterruptedException {
		while (ch.isActive()) {
			Packet pkt = ch.acquire();

			// same worker loop as live capture — no changes needed here
			analyzePacket(pkt);

			ch.release(pkt);
		}
	}

	void printReplayMetrics(Replay replay) {
		System.out.printf("Replay complete:%n");
		System.out.printf("  Dispatched: %,d packets%n", replay.packetsDispatched());
		System.out.printf("  Filtered:   %,d packets%n", replay.packetsFiltered());
		System.out.printf("  Dropped:    %,d packets%n", replay.packetsDropped());
	}

	void analyzePacket(Packet pkt) {
		// protocol analysis
	}
}