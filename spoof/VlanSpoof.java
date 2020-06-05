package net.floodlightcontroller.vlan_spoof.spoof;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;

public class VlanSpoof implements IFloodlightModule,IOFMessageListener{
	protected IFloodlightProviderService floodlightProviderService;
	private static String configFile = "/home/rishabh/.local/bin/nw_scripts/bin/spoofed_vlan";
	private BufferedReader fileReader;
	private ArrayList<IPv4Address> spoofingList;
	protected static Logger log = LoggerFactory.getLogger(VlanSpoof.class);
	@Override
	public String getName() {
		return "VlanSpoof";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return name.equals("forwarding") || name.equals("dhcpserver") || name.equals("ArpAuthenticator");
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if(msg.getType().equals(OFType.PACKET_IN)){
			return handlePacketInMessage(sw,(OFPacketIn)msg,cntx);
		}
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		try{
			fileReader = new BufferedReader(new FileReader(configFile));
		}catch(Exception e){
			log.error("Cannot open file " + configFile);
		}
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		String line;
		try{
			while((line = fileReader.readLine()) != null){
				IPv4Address addr = IPv4Address.of(line);
				spoofingList.add(addr);
			}
		}catch(Exception e){
			log.error("Error while reading file : "+configFile);
		}
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
	}

	private Command handlePacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx){
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		if(!eth.getEtherType().equals(EthType.ARP)){
			return Command.CONTINUE;
		}
		ARP arp = (ARP) eth.getPayload();
		if(spoofingList.contains(arp.getSenderProtocolAddress())){
			short vlanId = eth.getVlanID();
			if(vlanId == 0){
				eth.setVlanID((short)1);
			}else{
				eth.setVlanID((short)0);
			}
			OFFactory factory = sw.getOFFactory();
			Match match = factory.buildMatch().setExact(MatchField.ETH_TYPE,EthType.ARP).setExact(MatchField.IN_PORT,inPort).build();
		}
		return Command.CONTINUE;
	}
}
