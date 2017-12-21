using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.AirPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Diagnostics;

namespace packetcapturething
{
    class Program
    {
        
        static void Main(string[] args)
        {
            try
            {
                string ver = SharpPcap.Version.VersionString;
                /* Print SharpPcap version */
                Console.WriteLine("SharpPcap {0}, Example6.DumpTCP.cs", ver);
                Console.WriteLine();

                /* Retrieve the device list */
                var devices = CaptureDeviceList.Instance;

                /*If no device exists, print error */
                if (devices.Count < 1)
                {
                    Console.WriteLine("No device found on this machine");
                    return;
                }

                Console.WriteLine("The following devices are available on this machine:");
            
                Console.WriteLine();

                int i = 0;

                /* Scan the list printing every entry */
                foreach (var dev in devices)
                {
                    /* Description */
                    Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                    i++;
                }

                Console.WriteLine();
                Console.Write("-- Please choose a device to capture: ");
                i = int.Parse(Console.ReadLine());

                var device = devices[i];

                //Register our handler function to the 'packet arrival' event
                device.OnPacketArrival +=
                    new PacketArrivalEventHandler(device_OnPacketArrival);

                // Open the device for capturing
                int readTimeoutMilliseconds = 1000;
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                //tcpdump filter to capture only TCP/IP packets
                //string filter = "ip and tcp and udp";
                //device.Filter = filter;

                //Console.WriteLine();
                //Console.WriteLine
                //    ("-- The following tcpdump filter will be applied: \"{0}\"",
                //    filter);
                Console.WriteLine
                    ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                    device.Description);

                // Start capture 'INFINTE' number of packets
                device.Capture();

                // Close the pcap device
                // (Note: this line will never be called since
                //  we're capturing infinite number of packets
                device.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message.ToString());
            }
        }

        /// <summary>
        /// Prints the time, length, src ip, src port, dst ip and dst port
        /// for each TCP/IP packet received on the network
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            string GetDomainName()
            {
                string _domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;

                Ping ping = new Ping();

                try
                {
                    PingReply reply = ping.Send(_domain);

                    if (reply.Status == IPStatus.Success)
                    {
                        return _domain;
                    }
                    else
                    {
                        return reply.Status.ToString();
                    }
                }
                catch (PingException pExp)
                {
                    if (pExp.InnerException.ToString() == "No such host is known")
                    {
                        return "Network not detected!";
                    }

                    return "Ping Exception";
                }
            }
            try
            {
              
                var time = e.Packet.Timeval.Date;
                var len = e.Packet.Data.Length;

                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

                var tcpPacket = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
               
                if (tcpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IpPacket)tcpPacket.ParentPacket;
                    System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                    System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                    string protocol = ipPacket.Protocol.ToString();
                    int srcPort = tcpPacket.SourcePort;
                    int dstPort = tcpPacket.DestinationPort;



                    //IPHostEntry host;
                    //not working yet
                    //host = Dns.GetHostEntry(srcIp);

                    Console.WriteLine("{0}:{1}:{2},{3} Len={4} {5}:{6} -> {7}:{8}  protocol: {9}",
                            time.Hour, time.Minute, time.Second, time.Millisecond, len,
                            srcIp, srcPort, dstIp, dstPort, protocol);





                }
                var udpPacket = (PacketDotNet.UdpPacket)packet.Extract(typeof(PacketDotNet.UdpPacket));
                if (udpPacket != null)
                {
                    var udppacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                    int des_udpport = udpPacket.DestinationPort;
                    int src_udpport = udpPacket.SourcePort;
                    byte[] udpdata = udpPacket.PayloadData;
                    
                        
                        string udpleng = udpPacket.Length.ToString();
                        Console.WriteLine("{0}:{1}:{2},{3} Len={4} sourceport: {5} -> {6}  protocol: UDP",
                         time.Hour, time.Minute, time.Second, time.Millisecond, len,
                         des_udpport, src_udpport);
                    

                    
                }
            }
            catch (Exception ex)
            {
                var st = new StackTrace(ex, true);
                var frame = st.GetFrame(0);
                var line = frame.GetFileLineNumber();
                Console.WriteLine(line);
                Console.WriteLine(ex.Message);
                Console.ReadLine();

            }

                

            }
        }
    }







