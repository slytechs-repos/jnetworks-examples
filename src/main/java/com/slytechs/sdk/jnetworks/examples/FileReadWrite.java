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

import static com.slytechs.sdk.jnetworks.storage.NetFile.OpenOption.*;

import java.io.IOException;

import com.slytechs.sdk.common.memory.MemoryUnit;
import com.slytechs.sdk.common.session.SessionShutdownException;
import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.net.CaptureMetrics;
import com.slytechs.sdk.jnetworks.storage.NetFile;
import com.slytechs.sdk.jnetworks.storage.Storage;
import com.slytechs.sdk.jnetworks.storage.index.IndexLocation;
import com.slytechs.sdk.jnetworks.storage.index.IndexType;
import com.slytechs.sdk.jnetworks.storage.volumes.Volume;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.stack.ProtocolStack;

/**
 * Simple capture example for jNetWorks SDK.
 * 
 * <p>
 * Demonstrates basic packet capture using the iterator API. Iterators allow
 * simplified session management, single threaded capture and processing without
 * any need for more advanced worker or thread management. Perfect for one off
 * jobs, near one-liners, and script or batch processing.
 * 
 * <p>
 * The entire example executes in the main platform thread.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class FileReadWrite {

	public static void main(String[] args) {
		new FileReadWrite().run();
	}

	public void run() {
		// Searches for commercial license or fallback on community license
		Net.activateLicense();

		// use DpdkBackend with DPDK capable NICs/Ports
		// use NtapiBackend with Napatech SmartNIC configured adapters/Ports
		try (Volume vol = Storage.mount("captures")) {

			PacketChannel reader = vol.packetChannel("mycapture");
			NetFile input = vol.open("mycapture.pcapng", READ)
					.filter("tcp")
					.assignTo(reader)
					.stack(new ProtocolStack())
					.apply();

			// Create sharded output with indexing
			PacketChannel writer = vol.packetChannel("writer");
			NetFile output = vol.create("output.pcapng", WRITE)
					.assignTo(writer)
					.shardEvery(1, MemoryUnit.GIGABYTES)
					.index(IndexType.SPARSE)
					.indexLocation(IndexLocation.SIDECAR)
					.compression("zstd")
					.apply();

			System.out.println("Input:  " + input);
			System.out.println("Output: " + output);

			try (TaskExecutor executor = vol.executor("mycapture")) {
				executor.fork(reader, writer, this::processPackets)
						.awaitCompletion();

			}

			CaptureMetrics metrics = input.metrics();
			System.out.printf("Capture complete: %d packets%n", metrics.packetsReceived());

		} catch (InterruptedException | IOException e) {
			e.printStackTrace();
		}
	}

	void processPackets(PacketChannel channel, PacketChannel writer) throws SessionShutdownException,
			InterruptedException {
		while (channel.isActive()) {
			Packet packet = channel.acquire();

//			writer.write(packet);

			channel.release(packet);
		}
	}
}