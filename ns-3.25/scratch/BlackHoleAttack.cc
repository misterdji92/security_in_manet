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
#include <fstream>
 #include <string>
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
	std::cout <<"Time :"<< Simulator::Now ().GetSeconds () << "\t PacketSize :" << p->GetSize() <<"\n";
}


int main (int argc, char *argv[])
{
  bool enableFlowMonitor = true;
	std::string phyMode ("DsssRate10Mbps");
	/*double distance = 500;  // m
	//uint32_t numNodes = 25;  // by default, 5x5
	double interval = 0.001; // seconds
	uint32_t packetSize = 600; // bytes */
	//uint32_t numPackets = 10000000;
	std::string rtslimit = "1500";

  CommandLine cmd;
  cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.Parse (argc, argv);

  //double TotalTime = 200.0;
  std::string rate ("2048bps");
  //std::string phyMode ("DsssRate11Mbps");

  /*Config::SetDefault  ("ns3::OnOffApplication::PacketSize",StringValue ("512"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate",  StringValue (rate)); */

  //Set Non-unicastMode rate to unicast mode
  //Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));

	// turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue (rtslimit));

//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer c; // ALL Nodes
  NodeContainer not_malicious;
  NodeContainer malicious;
  int NodeNumber = (25);
  c.Create(NodeNumber);
/*  Names::Add ("Node_1", c.Get (0));   // Give name to the objects
  Names::Add ("Node_2", c.Get (1));
  Names::Add ("Node_3", c.Get (2));
  Names::Add ("Node_4", c.Get (3));
  Names::Add ("Node_5", c.Get (4)); */

/*  not_malicious.Add(c.Get(0));
  not_malicious.Add(c.Get(2));
  malicious.Add(c.Get(3));
  not_malicious.Add(c.Get(1));
	not_malicious.Add(c.Get(4)); */

for(int i=0; i<NodeNumber; i++) {
if( i==4 || i==14) {
  malicious.Add(c.Get(i));
} else {
  not_malicious.Add(c.Get(i));
}

}


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

  /*// Set 802.11b standard
  wifi.SetStandard (WIFI_PHY_STANDARD_80211n);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue(phyMode),
                                "ControlMode",StringValue(phyMode)); */
  wifi.SetStandard (WIFI_PHY_STANDARD_80211n_2_4GHZ);
wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue("HtMcs7"), "ControlMode", StringValue("HtMcs0"));


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

  // UDP connection from N3 to N5

  uint16_t sinkPort2 = 6;
  Address sinkAddress2 (InetSocketAddress (ifcont.GetAddress (4), sinkPort2)); // interface of n5
  PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort2));
  ApplicationContainer sinkApps2 = packetSinkHelper2.Install (c.Get (4)); //n5 as sink
  sinkApps2.Start (Seconds (0.));
  sinkApps2.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket2 = Socket::CreateSocket (c.Get (2), UdpSocketFactory::GetTypeId ()); //source at n3

  // Create UDP application at n3
  Ptr<MyApp> app2 = CreateObject<MyApp> ();
  app2->Setup (ns3UdpSocket2, sinkAddress2, 256, 1000, DataRate ("250Kbps"));
  c.Get (2)->AddApplication (app2);
  app2->SetStartTime (Seconds (20.));
  app2->SetStopTime (Seconds (100.));



  uint16_t sinkPort = 6;
  Address sinkAddress (InetSocketAddress (ifcont.GetAddress (9), sinkPort)); // interface of n9
  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (c.Get (9)); //n9 as sink
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket = Socket::CreateSocket (c.Get (1), UdpSocketFactory::GetTypeId ()); //source at n2

  // Create UDP application at n2
  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (ns3UdpSocket, sinkAddress, 256, 1000, DataRate ("250Kbps"));
  c.Get (1)->AddApplication (app);
  app->SetStartTime (Seconds (30.));
  app->SetStopTime (Seconds (100.));




  uint16_t sinkPort3 = 6;
  Address sinkAddress3 (InetSocketAddress (ifcont.GetAddress (17), sinkPort3)); // interface of n18
  PacketSinkHelper packetSinkHelper3 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort3));
  ApplicationContainer sinkApps3 = packetSinkHelper3.Install (c.Get (17)); //n18 as sink
  sinkApps3.Start (Seconds (0.));
  sinkApps3.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket3 = Socket::CreateSocket (c.Get (0), UdpSocketFactory::GetTypeId ()); //source at n1

  // Create UDP application at n1
  Ptr<MyApp> app3 = CreateObject<MyApp> ();
  app3->Setup (ns3UdpSocket3, sinkAddress3, 256, 1000, DataRate ("250Kbps"));
  c.Get (0)->AddApplication (app3);
  app3->SetStartTime (Seconds (50.));
  app3->SetStopTime (Seconds (100.));



    uint16_t sinkPort4 = 6;
    Address sinkAddress4 (InetSocketAddress (ifcont.GetAddress (23), sinkPort4)); // interface of n24
    PacketSinkHelper packetSinkHelper4 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort4));
    ApplicationContainer sinkApps4 = packetSinkHelper4.Install (c.Get (23)); //n5 as sink
    sinkApps4.Start (Seconds (0.));
    sinkApps4.Stop (Seconds (100.));

    Ptr<Socket> ns3UdpSocket4 = Socket::CreateSocket (c.Get (12), UdpSocketFactory::GetTypeId ()); //source at n13

    // Create UDP application at n13
    Ptr<MyApp> app4 = CreateObject<MyApp> ();
    app4->Setup (ns3UdpSocket4, sinkAddress4, 256, 1000, DataRate ("250Kbps"));
    c.Get (12)->AddApplication (app4);
    app4->SetStartTime (Seconds (70.));
    app4->SetStopTime (Seconds (100.));




/*

  uint16_t sinkPort = 6;
  Address sinkAddress (InetSocketAddress (ifcont.GetAddress (40), sinkPort)); // interface of n41
  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (c.Get (40)); //n5 as sink
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket = Socket::CreateSocket (c.Get (15), UdpSocketFactory::GetTypeId ()); //source at n16

  // Create UDP application at n16
  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (ns3UdpSocket, sinkAddress, 512, 50, DataRate ("250Kbps"));
  c.Get (15)->AddApplication (app);
  app->SetStartTime (Seconds (22.));
  app->SetStopTime (Seconds (100.));

*/


// Set Mobility for all nodes
/*
MobilityHelper mobility;
ObjectFactory pos;
pos.SetTypeId ("ns3::RandomRectanglePositionAllocator"); */

/*  pos.Set ("X", RandomVariableValue (UniformVariable (0.0, m_gridSize)));
pos.Set ("Y", RandomVariableValue (UniformVariable (0.0, m_gridSize))); */ /*
pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));


Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();

mobility.SetMobilityModel (
"ns3::RandomWaypointMobilityModel",
"Speed", StringValue("ns3::RandomVariableValue (ConstantVariable (100))"),
"Pause", StringValue("ns3::RandomVariableValue (ConstantVariable (10))"),
"PositionAllocator", PointerValue (taPositionAlloc));

mobility.SetPositionAllocator (taPositionAlloc);
mobility.Install (c); */

/*MobilityHelper mobility;
mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                               "MinX", DoubleValue (0.0),
                               "MinY", DoubleValue (0.0),
                               "DeltaX", DoubleValue (5.0),
                               "DeltaY", DoubleValue (10.0),
                               "GridWidth", UintegerValue (5),
                               "LayoutType", StringValue ("RowFirst"));

mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                           "Bounds", RectangleValue (Rectangle (-100, 100, -100, 100)));
mobility.Install (c); */


int nodeSpeed = 20; //in m/s
int nodePause = 3; //in s

MobilityHelper mobilityAdhoc;
//int64_t streamIndex = 0; // used to get consistent mobility across scenarios

ObjectFactory pos;
pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));
pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=800.0]"));

Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
//streamIndex += taPositionAlloc->AssignStreams (streamIndex);

std::stringstream ssSpeed;
ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
std::stringstream ssPause;
ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
mobilityAdhoc.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                "Speed", StringValue (ssSpeed.str ()),
                                "Pause", StringValue (ssPause.str ()),
                                "PositionAllocator", PointerValue (taPositionAlloc));
mobilityAdhoc.SetPositionAllocator (taPositionAlloc);
mobilityAdhoc.Install (c);
//streamIndex += mobilityAdhoc.AssignStreams (c, streamIndex);

//xionghu.uestc@gmail.com

/// There is sth i have added to the mobility thing that is making my visualizer to give error when simulating

/* AnimationInterface anim ("Output-Files/BlackHole/blackhole.xml"); // Mandatory
  AnimationInterface::SetConstantPosition (c.Get (0), 0, 500);
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
  AnimationInterface::SetConstantPosition (c.Get (11), 680, 500);
 anim.EnablePacketMetadata(true); */

      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("Output-Files/BlackHole/blackhole.routes", std::ios::out);
      aodv.PrintRoutingTableAllAt (Seconds (45), routingStream);

		Ptr<OutputStreamWrapper> routingStream1 = Create<OutputStreamWrapper> ("Output-Files/BlackHole/blackhole1.routes", std::ios::out);
			malicious_aodv.PrintRoutingTableAllAt (Seconds (95), routingStream1);


  // Trace Received Packets
  Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivePacket));


//
// Calculate Throughput using Flowmonitor
//
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();



//Tracing using Pcaps files
 AsciiTraceHelper ascii;
  wifiPhy.EnablePcapAll ("Output-Files/BlackHole/BHA");



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
      if ( (t.sourceAddress == "10.1.2.2" && t.destinationAddress == "10.1.2.10") || (t.sourceAddress == "10.1.2.3" && t.destinationAddress == "10.1.2.5") || (t.sourceAddress == "10.1.2.1" && t.destinationAddress == "10.1.2.18") || (t.sourceAddress == "10.1.2.13" && t.destinationAddress == "10.1.2.24") || (t.sourceAddress == "10.1.2.16" && t.destinationAddress == "10.1.2.40"))
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
