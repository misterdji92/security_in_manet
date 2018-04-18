/* Blackhole Attack Simulation with AODV Routing Protocol - Sample Program
 *
 * Network topology
 *
 *    n0 ------------> n1 ------------> n2 -------------> n3
 *
 * Each node is in the range of its immediate adjacent.
 * Source Node: n1
 * Destination Node: n3
 * Malicious Node: n0
 *
 * Output of this file:
 * 1. Generates blackhole.routes file for routing table information and
 * 2. blackhole.xml file for viewing animation in NetAnim.
 *
 */
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "myapp.h"

NS_LOG_COMPONENT_DEFINE ("Blackhole");

using namespace ns3;



void
ReceivePacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}


int main (int argc, char *argv[])
{
  bool enableFlowMonitor = true;
	std::string phyMode ("DsssRate1Mbps");
	/*double distance = 500;  // m
	//uint32_t numNodes = 25;  // by default, 5x5
	double interval = 0.001; // seconds
	uint32_t packetSize = 600; // bytes
	uint32_t numPackets = 10000000; */
	std::string rtslimit = "1500";

  CommandLine cmd;
  cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.Parse (argc, argv);


	// turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue (rtslimit));

//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer c; // ALL Nodes
  NodeContainer not_malicious;
  NodeContainer malicious;
  c.Create(12);

  not_malicious.Add(c.Get(0));
  not_malicious.Add(c.Get(2));
  not_malicious.Add(c.Get(3));
	not_malicious.Add(c.Get(4));
  not_malicious.Add(c.Get(5));
  not_malicious.Add(c.Get(6));
	not_malicious.Add(c.Get(8));
  malicious.Add(c.Get(7));
  not_malicious.Add(c.Get(9));
	not_malicious.Add(c.Get(10));
	not_malicious.Add(c.Get(11));
  malicious.Add(c.Get(1));
  // Set up WiFi
  WifiHelper wifi;

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11);

  YansWifiChannelHelper wifiChannel ;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::TwoRayGroundPropagationLossModel",
	  	  	  	  	  	  	  	    "SystemLoss", DoubleValue(1),
		  	  	  	  	  	  	    "HeightAboveZ", DoubleValue(1.5));

  // For range near 250m
  wifiPhy.Set ("TxPowerStart", DoubleValue(33));
  wifiPhy.Set ("TxPowerEnd", DoubleValue(33));
  wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
  wifiPhy.Set ("TxGain", DoubleValue(0));
  wifiPhy.Set ("RxGain", DoubleValue(0));
  wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue(-61.8));
  wifiPhy.Set ("CcaMode1Threshold", DoubleValue(-64.8));

  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifiMac.SetType ("ns3::AdhocWifiMac");

  // Set 802.11b standard
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue(phyMode),
                                "ControlMode",StringValue(phyMode));


  NetDeviceContainer devices;
  devices = wifi.Install (wifiPhy, wifiMac, c);


//  Enable AODV
  AodvHelper aodv;
  AodvHelper malicious_aodv;


  // Set up internet stack
  InternetStackHelper internet;
  internet.SetRoutingHelper (aodv);
  internet.Install (not_malicious);

  malicious_aodv.Set("IsMalicious",BooleanValue(true)); // putting *false* instead of *true* would disable the malicious behavior of the node
  internet.SetRoutingHelper (malicious_aodv);

  internet.Install (malicious);

  // Set up Addresses
  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer ifcont = ipv4.Assign (devices);


  NS_LOG_INFO ("Create Applications.");

  // UDP connection from N1 to N3

  uint16_t sinkPort2 = 6;
  Address sinkAddress2 (InetSocketAddress (ifcont.GetAddress (3), sinkPort2)); // interface of n3
  PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort2));
  ApplicationContainer sinkApps2 = packetSinkHelper2.Install (c.Get (3)); //n3 as sink
  sinkApps2.Start (Seconds (0.));
  sinkApps2.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket2 = Socket::CreateSocket (c.Get (0), UdpSocketFactory::GetTypeId ()); //source at n1

  // Create UDP application at n1
  Ptr<MyApp> app2 = CreateObject<MyApp> ();
  app2->Setup (ns3UdpSocket2, sinkAddress2, 1040, 5, DataRate ("250Kbps"));
  c.Get (0)->AddApplication (app2);
  app2->SetStartTime (Seconds (20.));
  app2->SetStopTime (Seconds (100.));





	// UDP connection from N7 to N9

	uint16_t sinkPort3 = 6;
	Address sinkAddress3 (InetSocketAddress (ifcont.GetAddress (9), sinkPort3)); // interface of n9
	PacketSinkHelper packetSinkHelper3 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort3));
	ApplicationContainer sinkApps3 = packetSinkHelper3.Install (c.Get (9)); //n9 as sink
	sinkApps3.Start (Seconds (0.));
	sinkApps3.Stop (Seconds (100.));

	Ptr<Socket> ns3UdpSocket3 = Socket::CreateSocket (c.Get (6), UdpSocketFactory::GetTypeId ()); //source at n7

	// Create UDP application at n1
	Ptr<MyApp> app3 = CreateObject<MyApp> ();
	app3->Setup (ns3UdpSocket3, sinkAddress3, 1040, 5, DataRate ("250Kbps"));
	c.Get (6)->AddApplication (app3);
	app3->SetStartTime (Seconds (10.));
	app3->SetStopTime (Seconds (100.));





	// UDP connection from N5 to N11

	uint16_t sinkPort = 6;
	Address sinkAddress (InetSocketAddress (ifcont.GetAddress (4), sinkPort)); // interface of n9
	PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
	ApplicationContainer sinkApps = packetSinkHelper.Install (c.Get (10)); //n11 as sink
	sinkApps.Start (Seconds (0.));
	sinkApps.Stop (Seconds (100.));

	Ptr<Socket> ns3UdpSocket = Socket::CreateSocket (c.Get (4), UdpSocketFactory::GetTypeId ()); //source at n7

	// Create UDP application at n1
	Ptr<MyApp> app = CreateObject<MyApp> ();
	app->Setup (ns3UdpSocket, sinkAddress, 1040, 5, DataRate ("250Kbps"));
	c.Get (4)->AddApplication (app);
	app->SetStartTime (Seconds (15.));
	app->SetStopTime (Seconds (100.));






// Set Mobility for all nodes

  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
  positionAlloc ->Add(Vector(100, 0, 0)); // node0
  positionAlloc ->Add(Vector(200, 0, 0)); // node1
  positionAlloc ->Add(Vector(450, 0, 0)); // node2
  positionAlloc ->Add(Vector(550, 0, 0)); // node3
	positionAlloc ->Add(Vector(140, 40, 0)); // node4
  positionAlloc ->Add(Vector(240, 40, 0)); // node5
  positionAlloc ->Add(Vector(490, 40, 0)); // node6
  positionAlloc ->Add(Vector(590, 40, 0)); // node7
	positionAlloc ->Add(Vector(180, 80, 0)); // node8
  positionAlloc ->Add(Vector(280, 80, 0)); // node9
  positionAlloc ->Add(Vector(530, 80, 0)); // node10
  positionAlloc ->Add(Vector(630, 80, 0)); // node11
  mobility.SetPositionAllocator(positionAlloc);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(c);

/// There is sth i have added to the mobility thing that is making my visualizer to give error when simulating

 AnimationInterface anim ("blackhole.xml"); // Mandatory
/*  AnimationInterface::SetConstantPosition (c.Get (0), 0, 500);
  AnimationInterface::SetConstantPosition (c.Get (1), 200, 500);
  AnimationInterface::SetConstantPosition (c.Get (2), 400, 500);
  AnimationInterface::SetConstantPosition (c.Get (3), 600, 500);
	AnimationInterface::SetConstantPosition (c.Get (4), 40, 500);
  AnimationInterface::SetConstantPosition (c.Get (5), 240, 500);
  AnimationInterface::SetConstantPosition (c.Get (6), 440, 500);
  AnimationInterface::SetConstantPosition (c.Get (7), 640, 500);
	AnimationInterface::SetConstantPosition (c.Get (8), 80, 500);
  AnimationInterface::SetConstantPosition (c.Get (9), 280, 500);
  AnimationInterface::SetConstantPosition (c.Get (10), 480, 500);
  AnimationInterface::SetConstantPosition (c.Get (11), 680, 500); */
  anim.EnablePacketMetadata(true);

      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("blackhole.routes", std::ios::out);
      aodv.PrintRoutingTableAllAt (Seconds (45), routingStream);

		/*	Ptr<OutputStreamWrapper> routingStream1 = Create<OutputStreamWrapper> ("blackhole1.routes", std::ios::out);
			malicious_aodv.PrintRoutingTableAllAt (Seconds (45), routingStream1);*/


  // Trace Received Packets
  Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivePacket));


//
// Calculate Throughput using Flowmonitor
//
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();


//
// Now, do the actual simulation.
//
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds(100.0));
  Simulator::Run ();

  monitor->CheckForLostPackets ();

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      if ((t.sourceAddress=="10.1.2.5" && t.destinationAddress == "10.1.2.11") || (t.sourceAddress == "10.1.2.1" && t.destinationAddress == "10.1.2.4") || (t.sourceAddress == "10.1.2.7" && t.destinationAddress == "10.1.2.9"))
      {
          std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
					std::cout << "        Number of Packets transmited:   " << i->second.txPackets << "\n";
			    std::cout << "        Number of received Packets:   " << i->second.rxPackets << "\n";
			    std::cout << "        Number of Packets Lost:   " << i->second.txPackets - i->second.rxPackets << "\n";
      	  std::cout << "        Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
      }
     }

  monitor->SerializeToXmlFile("blackhole.flowmon", true, true);


}
