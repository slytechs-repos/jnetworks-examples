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
import java.util.concurrent.TimeoutException;

import com.slytechs.jnetworks.HashMode;
import com.slytechs.jnetworks.HostStream.PacketStream;
import com.slytechs.jnetworks.NetException;
import com.slytechs.jnetworks.network.Network;
import com.slytechs.jnetworks.network.Network.Configuration;
import com.slytechs.jnetworks.pcap.PcapFilter;
import com.slytechs.jnetworks.pcap.PcapNetwork;
import com.slytechs.jnetworks.network.PacketCapture;
import com.slytechs.jnetworks.util.concurrent.StructuredNetScope;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.pack.core.Ethernet;
import com.slytechs.protocol.pack.core.Ip4;
import com.slytechs.protocol.runtime.util.NotFound;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class Example2_MultiCpuCapture {
	public static void main(String[] args) throws NetException, NotFound {

		/* Datalink and Network layer service */
		try (Network network = new PcapNetwork()) {

			try (Configuration config = network.configuration()) {
				config.selectPorts("enp0s25", "lo", "bluetooth0");

				config.assignTraffic(0, 3)
						.color(7)
						.hash(HashMode.HASH_5TUPLE)
						.filter(new PcapFilter("ip and device port {0,1}"));
			}

			try (PacketCapture capture = network.packetCapture()) {
				PacketStream[] streams = capture.getStreamsInRange(0, 3);

				try (var scope = new StructuredNetScope.CloseOnStop<PacketStream>()) {

					// Stream worker thread
					scope.fork(streams, stream -> {
						Ethernet ethernet = new Ethernet();
						Ip4 ip4 = new Ip4();

						try {
							while (stream.isOpen()) {
								Packet packet = stream.get(1, TimeUnit.SECONDS);

								if (packet.hasHeader(ethernet)) {
									System.out.println(ethernet);
								}

								if (packet.hasHeader(ip4)) {
									System.out.println(ip4);
								}

								stream.release(packet);
							}
						} catch (InterruptedException | TimeoutException e) {}

					}); // End of worker thread

					scope.joinUntil(5, TimeUnit.MINUTES);

				} // Close structured scope - wait for capture stop
			} // Close PacketCapture
		}
	}
}
