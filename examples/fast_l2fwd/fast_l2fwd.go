package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	//"github.com/asavie/xdp"
	"github.com/jursonmo/xdp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	//"github.com/asavie/xdp/examples/dumpframes/ebpf"
	"github.com/jursonmo/xdp/examples/dumpframes/ebpf"
)

//  ./fast_l2fwd -inlink=eth0  -ipproto=1 -dstIp=192.168.0.1  -outlink=eth1 -dstMac=00:00:11:22:33:44
//  ./fast_l2fwd -inlink=eth0 -op=del  //delete prog from inlink dev
func main() {
	var inLinkName, outLinkNmae, dstMac, dstIp, op string
	var inLinkQueueID, ipproto int
	var redirectOnly bool
	flag.StringVar(&inLinkName, "inlink", "eth0", "Input network link name.")
	flag.IntVar(&inLinkQueueID, "inlinkqueue", 0, "The queue ID to attach to on input link.")
	flag.IntVar(&ipproto, "ipproto", 0, "ipproto, icmp:1")
	flag.StringVar(&outLinkNmae, "outlink", "eth1", "Output network link name")
	flag.StringVar(&dstMac, "dstMac", "00:00:11:22:33:44", "forward to dst mac")
	flag.StringVar(&dstIp, "dstIp", "192.168.1.1", "forward to dst mac")
	flag.StringVar(&op, "op", "add", "add or del prog id from inlink")
	flag.BoolVar(&redirectOnly, "redirectOnly", false, "just forward the packet that from inlink to outlink")
	flag.Parse()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	inIfindex := -1
	outIfindex := -1
	for _, iface := range interfaces {
		if iface.Name == inLinkName {
			inIfindex = iface.Index
		}
		if iface.Name == outLinkNmae {
			outIfindex = iface.Index
		}
	}

	if op == "del" {
		if inIfindex == -1 {
			fmt.Println("inlink flag invalid")
			return
		}
		err := ebpf.Detach(inIfindex)
		if err != nil {
			fmt.Println(err)
		}
		return
	}

	log.Printf("inLinkName: inIfindex=%d, outLinkNmae: outIfindex=%d \n", inIfindex, outIfindex)
	if inIfindex == -1 || outIfindex == -1 {
		fmt.Printf("invalid, inIfindex =%d, outIfindex:%d", inIfindex, outIfindex)
		return
	}

	dstmac, err := net.ParseMAC(dstMac)
	if err != nil {
		fmt.Printf("err:%v", err)
		return
	}
	dstip := net.ParseIP(dstIp)
	log.Printf("dstip:%v, len(dstip)=%d\n", dstip, len(dstip))
	dstipv4 := dstip.To4()
	program, err := ebpf.NewFastL2fwdProgram(ipproto, nil)
	if err != nil {
		fmt.Printf("err:%v", err)
		return
	}

	if redirectOnly {
		if err := program.TxPort.Put(uint32(inIfindex), uint32(outIfindex)); err != nil {
			log.Printf("failed to update TxPort: %v, key=value=%d\n", err, outIfindex)
			return
		}
		if err := program.TxPort.Put(uint32(outIfindex), uint32(inIfindex)); err != nil {
			log.Printf("failed to update TxPort: %v, key=value=%d\n", err, outIfindex)
			return
		}
		if err := program.AttachRedirectProgram(inIfindex); err != nil {
			fmt.Printf("AttachRedirectProgram err:%v", err)
			return
		}
		if err := program.AttachRedirectProgram(outIfindex); err != nil {
			fmt.Printf("AttachRedirectProgram err:%v", err)
			return
		}
		log.Printf("redirectOnly, forward the packet that from %s(%d) to %s(%d)\n", inLinkName, inIfindex, outLinkNmae, outIfindex)
		time.Sleep(time.Hour)
		return
	}

	err = program.AttachProgram(inIfindex)
	if err != nil {
		fmt.Printf("err:%v", err)
		return
	}
	defer program.Detach(inIfindex)

	xsk, err := xdp.NewSocket(inIfindex, inLinkQueueID, nil)
	if err != nil {
		fmt.Printf("NewSocket err:%v", err)
		return
	}
	err = program.RegisterSocket(inLinkQueueID, xsk.FD())
	if err != nil {
		log.Printf("RegisterSocket err:%v", err)
		return
	}
	defer program.UnregisterSocket(inLinkQueueID)

	log.Printf("get packet now\n")
	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n, true))
		}

		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)

			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				pktData := xsk.GetFrame(rxDescs[i])
				pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
				log.Printf("received frame:\n%s%+v", hex.Dump(pktData[:]), pkt)

				pktDip := getPacketDstIp(pkt)
				log.Printf("----pktDip:%v, need to match dstip is:%v------\n", pktDip, dstip)
				log.Printf("----pktDip:%02x%02x%02x%02x,-----\n", pktDip[0], pktDip[1], pktDip[2], pktDip[3])
				log.Printf("----dstip:%02x%02x%02x%02x,------\n", dstip[0], dstip[1], dstip[2], dstip[3])
				if bytes.Equal(pktDip[:4], dstipv4 /*dstip[12:16]*/) {
					err := program.RegisterL2fwdInfo(dstip[12:16], inIfindex, outIfindex, []byte(dstmac))
					if err != nil {
						log.Printf("err:%v\n", err)
						return
					}
				}
			}
		}
	}
}

func getPacketDstIp(packet gopacket.Packet) net.IP {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
		return ip.DstIP
	}
	return nil
}
