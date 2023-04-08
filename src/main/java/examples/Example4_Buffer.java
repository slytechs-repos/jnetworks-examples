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

import static com.slytechs.protocol.runtime.util.MemoryUnit.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnetworks.HashMode;
import com.slytechs.jnetworks.HostBuffer.PacketBuffer;
import com.slytechs.jnetworks.HostSegment.PacketSegment;
import com.slytechs.jnetworks.NetException;
import com.slytechs.jnetworks.constants.TablePersistance;
import com.slytechs.jnetworks.constants.UnmatchedClassification;
import com.slytechs.jnetworks.network.Network;
import com.slytechs.jnetworks.network.Network.Configuration;
import com.slytechs.jnetworks.ntapi.NapatechFilter;
import com.slytechs.jnetworks.network.PacketCapture;
import com.slytechs.jnetworks.packet.HostPacket;
import com.slytechs.jnetworks.pcap.PcapNetwork;
import com.slytechs.jnetworks.util.HostIterator;
import com.slytechs.jnetworks.util.concurrent.StructuredNetScope;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.pack.core.Ethernet;
import com.slytechs.protocol.pack.core.Ip4;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class Example4_Buffer {
	public static void main(String[] args) throws NetException {

		try (Network network = new PcapNetwork()) {

			try (Configuration config = network.configuration()) {
				config.assignTrafficRange(0, 3)
						.color(7)
						.hash(HashMode.HASH_5TUPLE)
						.filter(new NapatechFilter("(port == 0) && (Layer3Protocol == IP)"));

				config.ipfModeRange(4, 5)
						.tableSize(256, MEGABYTES)
						.timeout(1, TimeUnit.SECONDS)
						.tablePersistance(TablePersistance.LAST_FRAGMENT)
						.unmatchedClassification(UnmatchedClassification.ALL);
			}

			try (PacketCapture capture = network.packetCapture()) {
				PacketBuffer[] buffers = capture.getBuffersInRange(0, 4);

				try (var scope = new StructuredNetScope.CloseOnStop<PacketBuffer>()) {

					scope.fork(buffers, (PacketBuffer buffer) -> {

						Ethernet ethernet = new Ethernet();
						Ip4 ip4 = new Ip4();

						try {
							while (buffer.isOpen()) {
								PacketSegment segment = buffer.get();

								HostIterator<Packet> it = segment.iterator();
								while (it.hasNext()) {
									Packet packet = it.next();

									if (!packet.hasHeader(ethernet))
										break;
								}

								buffer.release(segment);
							}
						} catch (InterruptedException e) {}

						try {
							while (buffer.isOpen()) {
								try (PacketSegment segment = buffer.get()) {
									for (Packet packet : segment) {
										if (!packet.hasHeader(ip4))
											break;
									}
								}
							}
						} catch (InterruptedException e) {}

						try {
							while (buffer.isOpen()) {
								List<Packet> packets = new ArrayList<>();
								ByteBuffer backing = ByteBuffer
										.allocateDirect(MemoryUnit.MEGABYTES.toIntBytes(1));

								try (PacketSegment segment = buffer.get()) {
									long count = segment.count();
									for (long i = 0; i < count; i++) {
										Packet packet1 = segment.get(i + 0);
										Packet packet2 = segment.peek(i + 1);

										if (!packet1.hasHeader(ip4))
											break;

										if ((packet2 != null) && !packet2.hasHeader(ip4))
											break;

										HostPacket packet3 = new HostPacket();

										var packet4 = packet3.cloneTo(backing);

										backing.put(packet4.buffer());

										Packet clone = packet1.clone();
										packets.add(clone);

										/* Clone just the java packet fields */
										Packet copy1 = packet1.clone();
										Packet copy2 = packet1.cloneTo(backing);
										backing.put(packet1.descriptor().buffer());
										backing.put(packet1.buffer());
									}
								}
							}
						} catch (InterruptedException e) {}

					});

					scope.join();
				}
			}
		}

	}
}