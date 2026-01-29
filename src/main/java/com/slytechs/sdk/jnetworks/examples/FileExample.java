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
 * Demonstrates advanced file reading and writing with channel-based processing.
 *
 * <p>
 * The jNetworks storage API provides unified access to diverse storage
 * technologies and output formats through a flexible three-tier architecture:
 * </p>
 * 
 * <h2>Storage Architecture</h2>
 * 
 * <pre>
 * Storage (Backend) → Volume (Mount Point) → NetFile (File Entity)
 * </pre>
 * 
 * <h2>What are SILOs?</h2>
 * <p>
 * SILO (Structured Independent Log Output) plugins transform packet capture
 * data into different output formats without modifying the original capture.
 * Common use cases:
 * </p>
 * <ul>
 * <li><b>Suricata EVE:</b> Convert PCAP to Suricata's EVE JSON format for SIEM
 * ingestion</li>
 * <li><b>Zeek Logs:</b> Generate Zeek-compatible logs from packet captures</li>
 * <li><b>Parquet:</b> Export to columnar format for analytics and data
 * science</li>
 * <li><b>Elasticsearch:</b> Stream packets directly to Elasticsearch for
 * real-time search</li>
 * <li><b>Custom JSON:</b> Transform to application-specific JSON schemas</li>
 * </ul>
 * 
 * <h2>Three Initialization Patterns</h2>
 * 
 * <h3>Pattern 1: SPI Discovery (Recommended)</h3>
 * <p>
 * Storage provider is automatically discovered from the mount point URI. The
 * storage implementation is loaded via Java SPI based on URI scheme.
 * </p>
 * 
 * <pre>{@code
 * // Local filesystem - discovers UnixStorage
 * try (Volume vol = Storage.mount("/captures")) {
 * 	// ... use volume
 * }
 * 
 * // S3 storage - discovers S3Storage plugin
 * try (Volume vol = Storage.mount("s3://my-bucket/captures")) {
 * 	// ... use volume
 * }
 * 
 * // ExaScale distributed - discovers ExaStorage plugin
 * try (Volume vol = Storage.mount("exa://cluster-east/prod")) {
 * 	// ... use volume
 * }
 * }</pre>
 * 
 * <h3>Pattern 2: Explicit Storage with Multiple Volumes</h3>
 * <p>
 * Create storage instance first, then mount multiple volumes. Useful when you
 * need shared configuration, credentials, or connection pooling across volumes.
 * </p>
 * 
 * <pre>{@code
 * // Explicit storage with credentials and settings
 * try (ExaStorage storage = new ExaStorage(credentials, settings)) {
 * 	storage.connect();
 * 
 * 	Volume prod = storage.mount("/prod");
 * 	Volume archive = storage.mount("/archive");
 * 
 * 	// Both volumes share storage backend
 * 	// ... use volumes
 * 
 * 	prod.unmount();
 * 	archive.unmount();
 * }
 * }</pre>
 * 
 * <h3>Pattern 3: Direct Volume Instantiation (Shortcut)</h3>
 * <p>
 * Skip Storage layer entirely and instantiate Volume directly. Storage backend
 * is created implicitly and managed automatically. Simplest pattern for
 * single-volume usage.
 * </p>
 * 
 * <pre>{@code
 * // UnixVolume implies UnixStorage backend
 * try (Volume vol = new UnixVolume("/captures")) {
 * 	// UnixStorage created and managed internally
 * 	// ... use volume
 * } // Auto-unmount and storage cleanup
 * 
 * // ExaVolume implies ExaStorage backend
 * try (Volume vol = new ExaVolume("cluster-east:/prod", credentials)) {
 * 	// ... use volume
 * }
 * }</pre>
 * 
 * <h2>This Example</h2>
 * <p>
 * Demonstrates Pattern 3 (Shortcut) with iterator-based processing, showing
 * how to:
 * </p>
 * <ul>
 * <li>Open and filter existing capture files</li>
 * <li>Create an iterator to read all of the packets</li>
 * <li>Process packets directly in the main thread</li>
 * </ul>
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

		// @formatter:off
		// Other storage types:
		//		- UnixStorage    - Local filesystem
		//		- S3Storage      - AWS S3, MinIO
		//		- ExaStorage     - Distributed ExaVolume
		//		- AzureStorage   - Azure Blob
		//		- GcsStorage     - Google Cloud Storage
		// @formatter:on

		// Use ExaStorage/ExaVolume for advanced capabilities.
		// Using a direct volume mount or
		// var unix = UnixStorage(); var volume = unix.mount("captures");

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