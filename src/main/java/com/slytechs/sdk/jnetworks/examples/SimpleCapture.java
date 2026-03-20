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

import com.slytechs.sdk.common.session.SessionException;
import com.slytechs.sdk.jnetworks.Net;
import com.slytechs.sdk.jnetworks.PacketIterator;
import com.slytechs.sdk.jnetworks.net.CaptureMetrics;
import com.slytechs.sdk.jnetworks.net.PortUnavailableException;
import com.slytechs.sdk.jnetworks.net.ResourceLimitException;
import com.slytechs.sdk.jnetworks.pcap.PcapBackend;

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
public class SimpleCapture {

	public static void main(String[] args) {
		new SimpleCapture().run();
	}

	public void run() {
		// use DpdkBackend with DPDK capable NICs/Ports
		// use NtapiBackend with Napatech SmartNIC configured adapters/Ports
		try (Net net = new PcapBackend();
				PacketIterator it = net.packetIterator("en0").apply()) {

			// or net.shutdownAfter(Duration.ofSeconds(15)) to shutdown main session
			it.shutdownAfter(Duration.ofSeconds(15));
			it.forEachRemaining("pkts %s"::formatted);

			CaptureMetrics metrics = it.metrics();
			System.out.printf("Capture complete: %d packets%n", metrics.packetsReceived());

		} catch (InterruptedException | PortUnavailableException | ResourceLimitException | SessionException e) {
			e.printStackTrace();
		}
	}
}