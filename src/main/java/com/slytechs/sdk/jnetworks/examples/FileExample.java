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

import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.PacketIterator;
import com.slytechs.sdk.jnetworks.net.CaptureMetrics;
import com.slytechs.sdk.jnetworks.storage.volumes.UnixVolume;
import com.slytechs.sdk.jnetworks.storage.volumes.Volume;

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
public class FileExample {

	public static void main(String[] args) {
		new FileExample().run();
	}

	public void run() {
		// Searches for commercial license or fallback on community license
		Net.activateLicense();

		// use DpdkBackend with DPDK capable NICs/Ports
		// use NtapiBackend with Napatech SmartNIC configured adapters/Ports
		try (Volume volume = new UnixVolume("captures");
				PacketIterator it = volume.packetIterator("mycapture.cap")) {

			it.forEachRemaining("pkts %s"::formatted);

			CaptureMetrics metrics = it.metrics();
			System.out.printf("Capture complete: %d packets%n", metrics.packetsReceived());

		} catch (InterruptedException | IOException e) {
			e.printStackTrace();
		}
	}
}