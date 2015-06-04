package uky.aag.l4lbapp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.action.SetNwDst;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.UDP;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.IPProtocols;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketHandler implements IListenDataPacket {

	// Important constant values for our application
	private static final String UDP_SRV_IP = "10.10.3.2";
	private static final String TCP_SRV_IP = "10.10.2.2";
    private static final byte[] UDP_SRV_MAC = {0,0,0,0,0,0x01};
    private static final byte[] TCP_SRV_MAC = {0,0,0,0,0,0x02};
    private static final String UDP_CONNECTOR_NAME = "eth1";
    private static final String TCP_CONNECTOR_NAME = "eth3";
	
	
	
	private static final Logger log = LoggerFactory.getLogger(PacketHandler.class);
	private IDataPacketService dataPacketService;
	private IFlowProgrammerService flowProgrammerService;
	private ISwitchManager switchManager;

	static private InetAddress intToInetAddress(int i) {
		byte b[] = new byte[] { (byte) ((i>>24)&0xff), (byte) ((i>>16)&0xff), (byte) ((i>>8)&0xff), (byte) (i&0xff) };
		InetAddress addr;
		try {
			addr = InetAddress.getByAddress(b);
		} catch (UnknownHostException e) {
			return null;
		}

		return addr;
	}

	/**
	 * (Un)Sets a reference to the requested DataPacketService
	 */
	void setDataPacketService(IDataPacketService s) {
		log.trace("Set DataPacketService.");

		dataPacketService = s;
	}
	void unsetDataPacketService(IDataPacketService s) {
		log.trace("Removed DataPacketService.");

		if (dataPacketService == s) {
			dataPacketService = null;
		}
	}

	/**
	 * (Un)Sets a reference to the requested FlowProgrammerService
	 */
	void setFlowProgrammerService(IFlowProgrammerService s) {
		log.trace("Set FlowProgrammerService.");

		flowProgrammerService = s;
	}
	void unsetFlowProgrammerService(IFlowProgrammerService s) {
		log.trace("Removed FlowProgrammerService.");

		if (flowProgrammerService == s) {
			flowProgrammerService = null;
		}
	}

	/**
	 * (Un)Sets a reference to the requested SwitchManagerService
	 */
	void setSwitchManagerService(ISwitchManager s) {
		log.trace("Set SwitchManagerService.");

		switchManager = s;
	}
	void unsetSwitchManagerService(ISwitchManager s) {
		log.trace("Removed SwitchManagerService.");

		if (switchManager == s) {
			switchManager = null;
		}
	}

	public PacketResult receiveDataPacket(RawPacket inPkt) {
		log.trace("Received data packet at controller:  " + inPkt.toString() );

		// Port where the packet arrived. 
		NodeConnector ingressConnector = inPkt.getIncomingNodeConnector();

		// Switch who has the above port. 
		Node node = ingressConnector.getNode();

		// Use DataPacketService to decode the packet.
		Packet l2frame = dataPacketService.decodeDataPacket(inPkt);

		if (l2frame instanceof Ethernet) {
			Object l3Pkt = l2frame.getPayload();
			if (l3Pkt instanceof IPv4) {
				IPv4 ipv4Pkt = (IPv4) l3Pkt;

				Packet segmt_or_dtgrm = ipv4Pkt.getPayload();

				if ( segmt_or_dtgrm instanceof UDP ) {
					UDP dtgrm = (UDP) segmt_or_dtgrm;
					int nwdst = ipv4Pkt.getDestinationAddress();
					InetAddress addr = intToInetAddress(nwdst);
					System.out.println( "UDP packet detected: = (" + addr + "," + dtgrm.getDestinationPort() + ")" );

					// Define the output port
					NodeConnector egressConnector;
					egressConnector = switchManager.getNodeConnector(node, UDP_CONNECTOR_NAME);

					// Make sure the outgoing port is set.
					if ( null == egressConnector ) {
						log.error( "Unable to set egressConnector." );
						return PacketResult.CONSUME;
					}

					// Create the match.
					Match match = new Match();
					match.setField( MatchType.DL_TYPE, EtherTypes.IPv4); 
					match.setField( MatchType.NW_PROTO, IPProtocols.UDP); 
					match.setField( MatchType.NW_DST, addr );
					match.setField( MatchType.TP_DST, dtgrm.getDestinationPort() ); 

					// List of actions.
					List<Action> actions = new LinkedList<Action>();
					actions.add(new SetDlDst(UDP_SRV_MAC));
					try {
						actions.add(new SetNwDst(InetAddress.getByName(UDP_SRV_IP)));
					} catch (UnknownHostException e) {
						log.error(e.getMessage());
					}
					actions.add( new Output( egressConnector ) );


					// Create the flow.
					Flow flow = new Flow( match, actions );
					flow.setPriority( (short) 1 ); // A priority that is higher than the typical UDP flow.
					flow.setIdleTimeout( (short) 20 ); // Timeout after 20 secs of inactivity.

					// Install the flow.
					Status flowStatus = flowProgrammerService.addFlow( node, flow );
					if ( ! flowStatus.isSuccess() ) {
						log.error( "Failed to install flow: " + flowStatus.getDescription() );
						return PacketResult.CONSUME;
					}

					// Forward this packet.
					inPkt.setOutgoingNodeConnector( egressConnector );
					dataPacketService.transmitDataPacket( inPkt );

					return PacketResult.CONSUME;
				
			
				}
			}
		}
		// We did not process the packet -> let someone else do the job.
		return PacketResult.IGNORED;
	}
}
