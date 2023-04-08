/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnetworks.examples;

import java.util.concurrent.TimeUnit;

import com.slytechs.jnetworks.HashMode;
import com.slytechs.jnetworks.HostStream;
import com.slytechs.jnetworks.NetException;
import com.slytechs.jnetworks.constants.TablePersistance;
import com.slytechs.jnetworks.constants.UnmatchedClassification;
import com.slytechs.jnetworks.network.Network;
import com.slytechs.jnetworks.network.Network.Configuration;
import com.slytechs.jnetworks.ntapi.NapatechFilter;
import com.slytechs.jnetworks.pcap.PcapNetwork;
import com.slytechs.jnetworks.transport.DataStreamReassembly;
import com.slytechs.jnetworks.transport.DataStreamSegment;
import com.slytechs.jnetworks.transport.Transport;
import com.slytechs.jnetworks.transport.Transport.TransportConfiguration;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class Example6_StreamReassembly {
	public static void main(String[] args) throws NetException {

		try (Network network = new PcapNetwork()) {

			try (Configuration config = network.configuration()) {
				config.assignTrafficRange(0, 3)
						.color(7)
						.hash(HashMode.HASH_5TUPLE)
						.filter(new NapatechFilter("(port == 0) && (Layer3Protocol == IP)"));

				config.ipfModeRange(4, 5)
						.tableSize(256, MemoryUnit.MEGABYTES)
						.timeout(1, TimeUnit.SECONDS)
						.tablePersistance(TablePersistance.LAST_FRAGMENT)
						.unmatchedClassification(UnmatchedClassification.ALL);
			}

			try (Transport transport = network.transport()) {

				try (TransportConfiguration config = transport.configuration()) {
					config.enableReassembly(true)
							.enableSegmentPassthrough(false);

					config.assignTraffic()
							.hash(HashMode.HASH_5TUPLE_SORTED);
				}

				try (DataStreamReassembly capture = transport.dataStreamReassembly();
						HostStream<DataStreamSegment> segments = capture.getStream(0)) {

					while (segments.isOpen()) {
						try (DataStreamSegment descriptor = segments.get()) {

						} catch (InterruptedException e) {
							capture.close();
						}
					}

				}

			}
		}

	}
}