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
import java.util.concurrent.TimeoutException;
import java.util.stream.IntStream;

import com.slytechs.jnetworks.HashMode;
import com.slytechs.jnetworks.HostStream.PacketStream;
import com.slytechs.jnetworks.NetException;
import com.slytechs.jnetworks.network.Network;
import com.slytechs.jnetworks.network.Network.Configuration;
import com.slytechs.jnetworks.network.Network.Information;
import com.slytechs.jnetworks.network.PacketCapture;
import com.slytechs.jnetworks.pcap.PcapFilter;
import com.slytechs.jnetworks.pcap.PcapNetwork;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.pack.core.Ethernet;
import com.slytechs.protocol.pack.core.Ip4;
import com.slytechs.protocol.runtime.NotFound;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class Example1_PacketCapture {
	public static void main(String[] args) throws NetException, NotFound {

		/* Datalink and Network layer service */
		try (Network network = new PcapNetwork()) {

			try (Information info = network.information()) {
				String[] ports = info.listPorts();

				IntStream.range(0, ports.length)
						.mapToObj(idx ->
						{
							String name = ports[idx];
							String dlt = info.portDltName(ports[idx]);

							return "port=%d [name=%s/dlt=%s]".formatted(idx, name, dlt);
						})
						.forEach(System.out::println);
			}

			try (Configuration config = network.configuration()) {

				// @formatter:off
				config.selectPorts(
						"enp0s25",           // Port #0
						"lo",                // Port #1
						"bluetooth0"         // Port #2
				);
				// @formatter:on

				config.assignTraffic(0, 3)
						.color(7)
						.hash(HashMode.HASH_5TUPLE)
						.filter(new PcapFilter("device port {0, 1} and ip"));

				config.assignTraffic()
						.priority(1)
						.dropPackets()
						.filter(new PcapFilter("device port 2"));
			}

			try (PacketCapture capture = network.packetCapture()) {
				PacketStream stream = capture.getStream(0);

				Ethernet ethernet = new Ethernet();
				Ip4 ip4 = new Ip4();

				while (stream.isOpen()) {
					try (Packet packet = stream.get(1, TimeUnit.SECONDS)) {

						if (packet.hasHeader(ethernet)) {
							System.out.println(ethernet);
						}

						if (packet.hasHeader(ip4)) {
							System.out.println(ip4);
						}

					} catch (InterruptedException e) {
						stream.close();
					} catch (TimeoutException e1) {
						break;
					}
				}

				for (Packet packet : stream.packets()) {

				}

				stream.stream().forEach(System.out::println);

			}

		}
	}
}
