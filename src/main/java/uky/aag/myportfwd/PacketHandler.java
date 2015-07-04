package uky.aag.myportfwd;

/* For full class description and methods check:
 * https://developer.cisco.com/media/XNCJavaDocs/overview-summary.html
 */

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Drop;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.SetTpDst;
import org.opendaylight.controller.sal.action.SetTpSrc;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.packet.UDP;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.IPProtocols;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketHandler implements IListenDataPacket {

	// Important constant values for our application

	private static final Logger log = LoggerFactory.getLogger(PacketHandler.class);
	private IDataPacketService dataPacketService;
	private IFlowProgrammerService flowProgrammerService;
	private ISwitchManager switchManager;

	/* Configuration class for the port forwarding bundle*/
    public class PortFwdInfo {
        public short low_bound;
        public short up_bound;
        public short fwd_port;

        public PortFwdInfo(short lb, short ub, short port) {
            this.low_bound = lb;
            this.up_bound = ub;
            this.fwd_port = port;
        }

        public boolean inForwardingRange(short port){
        	return port >= low_bound && port <= up_bound;
        }

    }

    PortFwdInfo port_range;

    void init() {
    	/* Define the port range and port where traffic within this range will be forwarded to*/
        port_range = new PortFwdInfo((short)5000,(short)6000,(short)5050);
        // Remove any conflicting bundle
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding") ||
            		bundle.getSymbolicName().contains("arphandler")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    log.error("Exception in Bundle uninstall "+e.getMessage());
                }
            }
        }

        log.info("Initialized");
    }

	static private InetAddress intToInetAddress(int i) {
		InetAddress addr;
		try {
			addr = InetAddress.getByAddress(BitBufferHelper.toByteArray(i));
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

	/* Method that handles Packet-In events. Where all the flow logic is implemented */
	public PacketResult receiveDataPacket(RawPacket inPkt) {
		log.trace("Received data packet at controller: " );

		// Determine incoming port and node, and decode received packet.
		NodeConnector in_port = inPkt.getIncomingNodeConnector();
		Node node = in_port.getNode();
		Packet l2frame = dataPacketService.decodeDataPacket(inPkt);

		if (l2frame instanceof Ethernet) {
			Packet l3Pkt = l2frame.getPayload();
//			System.out.println("Ethernet: " + l2frame.toString());
			/*If needed you can extract MAC addresses from l3Pkt */
			if (l3Pkt instanceof IPv4) {
				IPv4 ipv4Pkt = (IPv4) l3Pkt;
//				System.out.println("IPv4 " + ipv4Pkt.toString());
				Packet segmt_or_dtgrm = ipv4Pkt.getPayload();
				int nwdst = ipv4Pkt.getDestinationAddress();
				int nwsrc = ipv4Pkt.getSourceAddress();
				InetAddress dst_addr = intToInetAddress(nwdst);
				InetAddress src_addr = intToInetAddress(nwsrc);
				if ( segmt_or_dtgrm instanceof TCP ) {
					TCP segmt = (TCP) segmt_or_dtgrm;
					System.out.println(segmt.toString());
					short dstport = segmt.getDestinationPort();
					short srcport = segmt.getSourcePort();

					NodeConnector out_port = getOutPort(in_port);

					/* Create match for incoming flow*/
					Match match = new Match();
					List<Action> actions = new LinkedList<Action>();

					match.setField( MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
					match.setField( MatchType.NW_PROTO, IPProtocols.TCP.byteValue());
					match.setField( MatchType.NW_SRC, src_addr);
					match.setField( MatchType.NW_DST, dst_addr);
					match.setField( MatchType.TP_DST, dstport );
					match.setField( MatchType.TP_SRC, srcport );
					/* If dst port is in the forwarding range install
					 * two-way flows with reversed match fields for reply messages.
					 */
					Match reverse_match = match.reverse();
					List<Action> ractions = new LinkedList<Action>();

					if (port_range.inForwardingRange(dstport)){
						actions.add(new SetTpDst(port_range.fwd_port)); // Port-forwarding occurs here
						actions.add( new Output( out_port));
						segmt.setDestinationPort(port_range.fwd_port); // Modify original packet likewise.

						reverse_match.setField(MatchType.TP_SRC, port_range.fwd_port);
						ractions.add(new SetTpSrc(dstport));
						ractions.add(new Output(in_port));

						Status st = programFlow(node,match,actions,(short)10,(short)40);
						st = programFlow(node, reverse_match, ractions, (short)10,(short)40);
						// Handle flow installation errors.
						if ( ! st.isSuccess() ) {
							log.trace( "Failed to install flow: " + st.getDescription() );
							return PacketResult.IGNORED;
						}
						inPkt.setOutgoingNodeConnector( out_port );
						dataPacketService.transmitDataPacket( inPkt );
					} else if (segmt.toString().contains("SequenceNumber: 00000000")){
						/* Sometimes the second packet from the 3-way handshake is sent out
						 * before the the reverse flow is actually installed. Should this happen,
						 * the packet will be forwarded to the controller and ignored. */
						return PacketResult.IGNORED;
					} else {
						/* If the destination port is out of the defined range we will
						 * install a rule that will drop all the traffic directed to such
						 * port.
						 */
						actions.add(new Drop());
						/* Clear source port, otherwise a new flow will be installed for every
						 * new connection and we want to ban access to just the dest port.
						 */
						match.clearField(MatchType.TP_SRC);
						Status st = programFlow(node, match, actions ,(short)10,(short)120);
						return PacketResult.IGNORED;
					}
					// Forward this packet.
					return PacketResult.CONSUME;
				}
				else if ( segmt_or_dtgrm instanceof UDP ) {
					/* If UDP traffic is detected, we will install flow entries
					 * that allow any UDP traffic to go through (i.e. port fields are wildcarded
					 * but the network protocol will be set to UDP)
					 */
					UDP dtgrm = (UDP) segmt_or_dtgrm;
					short dstport = dtgrm.getDestinationPort();
					System.out.println( "UDP datagram detected: = (" + src_addr + " => " + dst_addr + " : " + dstport + ")" );

					NodeConnector out_port = getOutPort(in_port);
					// One way flow match
					Match match = new Match();
					match.setField( MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
					match.setField( MatchType.NW_PROTO, IPProtocols.UDP.byteValue());
					match.setField(MatchType.NW_SRC, src_addr);
					match.setField( MatchType.NW_DST, dst_addr);
					// Reverse match definition
					Match rmatch = new Match();
					rmatch.setField( MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
					rmatch.setField( MatchType.NW_PROTO, IPProtocols.UDP.byteValue());
					rmatch.setField(MatchType.NW_SRC,dst_addr );
					rmatch.setField( MatchType.NW_DST,src_addr );
					/* We do no modification to packet header*/
					List<Action> actions = new LinkedList<Action>();
					List<Action> ractions = new LinkedList<Action>();
					actions.add( new Output( out_port ) );
					ractions.add (new Output(in_port));

					// Install the flow into the switch's table.
					Status flowStatus = programFlow(node, match, actions, (short)10, (short)60);
					flowStatus = programFlow(node, rmatch, ractions, (short)10, (short)60);
					System.out.println("UDP Flow Status: " + flowStatus.getDescription());
					// Forward this packet.
					inPkt.setOutgoingNodeConnector( out_port );
					dataPacketService.transmitDataPacket( inPkt );
					return PacketResult.CONSUME;
				} // fi UDP/TCP
			} //fi IPv4
		} //fi Ethernet


		// We did not process the packet -> let someone else do the job.
		return PacketResult.IGNORED;
	}

	public NodeConnector getOutPort(NodeConnector in){
		NodeConnector out = null;
		// Get all the active ports on the switch
		Set<NodeConnector> ports = switchManager.getUpNodeConnectors( in.getNode() );

		// Find the first out-port that is different from the in-port.
		/* If switch only has two ports, it is the same as flooding.
		 * A more complex
		 * routine should be used for other applications like
		 * load balancers or traffic duplicators.*/
		Iterator<NodeConnector> i = ports.iterator();
		while ( i.hasNext() ) {
			NodeConnector temp = i.next();
			if ( ! temp.equals( in ) ) {
				out = temp;
				break;
			}
		}
		return out;
	}
	/*Helper function for programming flows to clean out code */
	public Status programFlow(Node node, Match match, List<Action> actions, short prio, short st_out){
		Flow flow = new Flow(match,actions);
		flow.setPriority(prio);
		flow.setIdleTimeout(st_out);
		System.out.println("Installing " + match.getField(MatchType.NW_PROTO).toString() + " flow : " + flow.toString());
		return flowProgrammerService.addFlowAsync(node, flow );

	}
}
