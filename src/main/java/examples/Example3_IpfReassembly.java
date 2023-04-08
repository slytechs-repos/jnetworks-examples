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
package examples;

import java.util.concurrent.TimeUnit;

import com.slytechs.jnetworks.HashMode;
import com.slytechs.jnetworks.HostStream.PacketStream;
import com.slytechs.jnetworks.NetException;
import com.slytechs.jnetworks.constants.TablePersistance;
import com.slytechs.jnetworks.constants.UnmatchedClassification;
import com.slytechs.jnetworks.network.Network;
import com.slytechs.jnetworks.network.Network.Configuration;
import com.slytechs.jnetworks.ntapi.NapatechFilter;
import com.slytechs.jnetworks.pcap.PcapNetwork;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.pack.core.Ethernet;
import com.slytechs.protocol.pack.core.Ip4;
import com.slytechs.protocol.runtime.util.MemoryUnit;
import com.slytechs.jnetworks.network.PacketCapture;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class Example3_IpfReassembly {
	public static void main(String[] args) throws NetException {

		// Convention note: Network stands for jNetWorks (drop the 'j')
		try (Network network = new PcapNetwork()) {

			try (Configuration config = network.configuration()) {
				config.assignTraffic(0)
						.color(7)
						.hash(HashMode.HASH_5TUPLE)
						.filter(new NapatechFilter("(port == 0) && (Layer3Protocol == IP)"));

				config.ipfModeRange(1, 2)
						.tableSize(4, MemoryUnit.MEGABYTES)
						.timeout(1, TimeUnit.SECONDS)
						.tablePersistance(TablePersistance.LAST_FRAGMENT)
						.unmatchedClassification(UnmatchedClassification.ALL);

			}

			try (PacketCapture capture = network.packetCapture()) {
				PacketStream stream = capture.getStream(0);

				Ethernet ethernet = new Ethernet();
				Ip4 ip4 = new Ip4();

				while (stream.isOpen()) {
					try (Packet packet = stream.get()) {

						if (packet.hasHeader(ethernet)) {
							System.out.println(ethernet);
						}

						if (packet.hasHeader(ip4)) {
							System.out.println(ip4);
						}

					} catch (InterruptedException e) {
						break;
					}
				}
			}

		}

	}

}
