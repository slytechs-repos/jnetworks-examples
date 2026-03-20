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

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import com.slytechs.sdk.jnetworks.channels.PacketChannel;
import com.slytechs.sdk.jnetworks.concurrency.TaskExecutor;
import com.slytechs.sdk.jnetworks.device.Port;
import com.slytechs.sdk.jnetworks.device.VirtualPort;
import com.slytechs.sdk.jnetworks.net.Capture;
import com.slytechs.sdk.protocol.core.Packet;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class VirtualPorts {

	interface Net {

		Port port(String string);

		VirtualPort virtualPort(String string, PacketChannel exportChannelA);

		VirtualPort virtualPort(String string, Port txPort, PacketChannel exportChannelC);

		CaptureBuilder capture(String string, String string2);

		TaskExecutor executor(String string);

		interface CaptureBuilder {

			CaptureBuilder assignTo(PacketChannel[] capChannels);

			CaptureBuilder assignAfter(VirtualPort fileWriterA, VirtualPort fileWriterB, VirtualPort txAndExport);

			Capture apply();

			CaptureBuilder assignTo(int i, PacketChannel exportChannelD);

		}
	}

	/**
	 * 
	 */
	public VirtualPorts() {

		Net net = null;
		PacketChannel[] capChannels = null;
		PacketChannel exportChannelA = null, exportChannelB = null, exportChannelC = null, exportChannelD = null;

		Port txPort = net.port("en1");

		VirtualPort fileWriterA = net.virtualPort("writer-a", exportChannelA);
		VirtualPort fileWriterB = net.virtualPort("writer-b", exportChannelB);
		VirtualPort txAndExport = net.virtualPort("tx-export", txPort, exportChannelC); // fan-out

		Capture capture = net.capture("capture1", "en0")
				.assignTo(capChannels)
				.assignAfter(fileWriterA, fileWriterB, txAndExport) // declare destinations
				.apply();

		Capture capture2 = net.capture("capture2", "en1")
				.assignTo(8, exportChannelD)
				.apply();

		FileChannel fileA = null, fileB = null, fileC = null;

		TaskExecutor executor = net.executor("virtual-ports-executor");
		executor.fork(capChannels, (PacketChannel ch) -> {
			while (ch.isActive()) {
				Packet pkt = ch.acquire();
				if (isDnsExfil(pkt))
					pkt.tx().setTxPort(fileWriterA.index());
				else if (isHighValue(pkt))
					pkt.tx().setTxPort(txAndExport.index());
				else
					pkt.tx().setTxEnabled(false);
				ch.release(pkt);
			}
		})
				.fork(exportChannelA, fileA, (PacketChannel ch, FileChannel f) -> {
					while (ch.isActive()) {
						var pkt = ch.acquire();

						f.write(new ByteBuffer[] {
								pkt.descriptor().boundMemory().asByteBuffer(),
								pkt.boundMemory().asByteBuffer()
						});

						ch.release(pkt);
					}
				})
				.fork(exportChannelB, fileB, (ch, f) -> {
					while (ch.isActive()) {
						var pkt = ch.acquire();

						f.write(new ByteBuffer[] {
								pkt.descriptor().boundMemory().asByteBuffer(),
								pkt.boundMemory().asByteBuffer()
						});

						ch.release(pkt);
					}
				})
				.fork(exportChannelC, fileC, (ch, f) -> {
					while (ch.isActive()) {
						var pkt = ch.acquire();

						f.write(new ByteBuffer[] {
								pkt.descriptor().boundMemory().asByteBuffer(),
								pkt.boundMemory().asByteBuffer()
						});

						ch.release(pkt);
					}
				});
	}

	/**
	 * @param pkt
	 * @return
	 */
	private boolean isHighValue(Packet pkt) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @param pkt
	 * @return
	 */
	private boolean isDnsExfil(Packet pkt) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
