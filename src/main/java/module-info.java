/**
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @author repos@slytechs.com
 * 
 */
module com.slytechs.sdk.jnetworks.examples {
	requires com.slytechs.sdk.jnetworks;
	requires com.slytechs.sdk.jnetworks.pcap;
//	requires com.slytechs.sdk.jnetworks.dpdk;
	
	requires com.slytechs.sdk.common;
	requires com.slytechs.sdk.protocol.core;
	requires com.slytechs.sdk.protocol.tcpip;
	
	requires org.slf4j;
	requires ch.qos.logback.classic;
}