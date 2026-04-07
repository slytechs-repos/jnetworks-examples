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
import java.time.Duration;

import com.slytechs.sdk.common.session.SessionException;
import com.slytechs.sdk.jnetworks.PacketIterator;
import com.slytechs.sdk.jnetworks.net.PortUnavailableException;
import com.slytechs.sdk.jnetworks.net.ResourceLimitException;
import com.slytechs.sdk.jnetworks.storage.Storage;
import com.slytechs.sdk.jnetworks.storage.StorageMetrics;
import com.slytechs.sdk.jnetworks.storage.Volume;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.filter.FilterException;
import com.slytechs.sdk.protocol.core.filter.PacketFilter;

/**
 * Demonstrates sequential packet reading from a capture file.
 *
 * <p>
 * Three patterns are shown, ordered from simplest to most capable:
 * </p>
 *
 * <ul>
 * <li>{@link #readWithForEach()} — single call, packets processed and recycled
 *     automatically via {@code forEach}.</li>
 * <li>{@link #readWithIterator()} — for-each loop via {@link PacketIterator};
 *     each packet is an independent copy safe to store beyond the loop step.
 *     {@code shutdownAfter} bounds large files or looped replay.</li>
 * <li>{@link #readViaVolume()} — explicit {@link Volume} mount; suitable when
 *     reading multiple files from the same directory or a remote backend.</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class FileReadExample {

	public static void main(String[] args) throws IOException, PortUnavailableException, ResourceLimitException, SessionException, InterruptedException, FilterException {
		FileReadExample ex = new FileReadExample();
		ex.readWithForEach();
		ex.readWithIterator();
		ex.readLooped();
		ex.readViaVolume();
	}

	/**
	 * Simplest read pattern — forEach on the reader.
	 *
	 * Each packet passed to the callback is a pooled object recycled automatically
	 * after the callback returns. Do not store packet references beyond the lambda.
	 */
	void readWithForEach() throws IOException {
		try (Storage storage = Storage.open(Path.of("/captures/input.pcapng"))) {

			storage.reader().forEach(this::analyzePacket);

			printMetrics(storage.reader().metrics());
		}
	}

	/**
	 * For-each loop via PacketIterator.
	 *
	 * Each packet returned by the iterator is an independent copy — safe to add to
	 * a collection or reference after advancing the loop. Use shutdownAfter to
	 * bound iteration time for large files or when accessing remote storage.
	 * @throws FilterException 
	 * @throws InterruptedException 
	 * @throws SessionException 
	 * @throws ResourceLimitException 
	 * @throws PortUnavailableException 
	 */
	void readWithIterator() throws IOException, PortUnavailableException, ResourceLimitException, SessionException, InterruptedException, FilterException {
		try (Storage storage = Storage.open(Path.of("/captures/input.pcapng"))) {

			try (PacketIterator iter = storage.packetIterator()
					.filter(PacketFilter.tcp())
					.apply()) {

				iter.shutdownAfter(Duration.ofSeconds(30));

				for (Packet pkt : iter)
					analyzePacket(pkt);  // independent copy — safe to store
			}

			printMetrics(storage.reader().metrics());
		}
	}

	/**
	 * Looped read — restarts from the first packet when end-of-file is reached.
	 *
	 * loop(true) is set on the reader before creating the iterator. The iterator
	 * itself has no loop concept — it delegates to the reader underneath.
	 * shutdownAfter is required to bound an infinite loop.
	 * @throws InterruptedException 
	 * @throws SessionException 
	 * @throws ResourceLimitException 
	 * @throws PortUnavailableException 
	 */
	void readLooped() throws IOException, PortUnavailableException, ResourceLimitException, SessionException, InterruptedException {
		try (Storage storage = Storage.open(Path.of("/captures/input.pcapng"))) {

			storage.reader().loop(true);

			try (PacketIterator iter = storage.packetIterator().apply()) {

				iter.shutdownAfter(Duration.ofMinutes(5));

				for (Packet pkt : iter)
					analyzePacket(pkt);
			}

			storage.reader().stopLoop();  // reset for any subsequent read
		}
	}

	/**
	 * Reading via an explicit Volume.
	 *
	 * Useful when reading multiple files from the same directory, or when
	 * accessing a remote backend where establishing the connection is expensive.
	 * The volume connection is established once and reused across all openFile
	 * calls. Closing the volume does not close any Storage sessions opened
	 * through it — those are closed independently.
	 *
	 * For remote backends replace Volume.mount(Path) with:
	 *   Volume.mount(URI.create("s3://my-bucket/captures"), VolumeCredentials.fromEnv())
	 */
	void readViaVolume() throws IOException {
		try (Volume vol = Volume.mount(Path.of("/captures"))) {

			try (Storage f1 = vol.openFile("morning.pcapng");
			     Storage f2 = vol.openFile("afternoon.pcapng")) {

				f1.reader().forEach(this::analyzePacket);
				f2.reader().forEach(this::analyzePacket);

				System.out.printf("morning:   ");
				printMetrics(f1.reader().metrics());
				System.out.printf("afternoon: ");
				printMetrics(f2.reader().metrics());
			}
		}
	}

	void printMetrics(StorageMetrics m) {
		System.out.printf("%,d packets  %,d bytes  %.1f Mbps%n",
				m.packetsRead(), m.bytesRead(), m.mbps());

		m.filePacketCount().ifPresent(n ->
				System.out.printf("  File reported: %,d captured%n", n));
		m.fileDropCount().ifPresent(n ->
				System.out.printf("  File reported: %,d dropped at capture time%n", n));

		if (m.hasReadErrors())
			System.out.printf("  Warnings: %,d read errors (truncated file?)%n",
					m.readErrors());
	}

	void analyzePacket(Packet pkt) {
		// offline analysis — pkt is valid for the duration of this call when
		// using forEach; independent copy when using PacketIterator
	}
}