package main

import (
	"fmt"
	"net"

	"github.com/williamfhe/godivert"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func GenerateFilterString(exemptLocalhost bool) string {
	// We don't want to interrupt well-known, TCP based windows services that have nothing
	// to do with HTTP/HTTPS.
	// So, here we generate a WinDivert filter string that exempts such services.

	// This list of ports was taken from:
	// https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx?Redirected=true#List_of_Ports
	exemptedPorts := []int{
		7,     // Echo
		9,     // Discard
		13,    // Daytime
		17,    // Quotd
		19,    // Chargen
		20,    // FTP
		21,    // FTP
		23,    // Telnet
		25,    // SMTP
		42,    // WINS
		53,    // DNS
		88,    // Kerberos
		102,   // X.400
		110,   // POP3
		119,   // NNTP
		135,   // RPC
		139,   // NetBIOS
		143,   // IMAP
		389,   // LDAP
		445,   // SMB
		464,   // Kerberos
		515,   // LPD
		548,   // File
		554,   // RTSP
		563,   // NNTP
		593,   // RPC
		636,   // LDAP
		993,   // IMAP
		995,   // POP3
		1067,  // Installation
		1068,  // Installation
		1270,  // MOM-Encrypted
		1433,  // SQL
		1723,  // PPTP
		1755,  // MMS
		1801,  // MSMQ
		2101,  // MSMQ-DCs
		2103,  // MSMQ-RPC
		2105,  // MSMQ-RPC
		2107,  // MSMQ-Mgmt
		2393,  // OLAP
		2394,  // OLAP
		2701,  // SMS
		2702,  // SMS
		2703,  // SMS
		2704,  // SMS
		2725,  // SQL
		2869,  // UPNP / SSDP
		3268,  // Global
		3269,  // Global
		3389,  // Terminal
		5000,  // SSDP
		5722,  // RPC
		6001,  // Information
		6002,  // Directory
		6004,  // DSProxy/NSPI
		42424, // ASP.Net
		51515, // MOM-Clear
	}

	var filter string
	for _, port := range exemptedPorts {
		filter += (" and tcp.DstPort != " + fmt.Sprint(port))
	}

	switch exemptLocalhost {
	case true:
		{
			filter = ("outbound and tcp and tcp.SrcPort == 8080 and tcp.DstPort == 80 and ((ip and ip.SrcAddr != 127.0.0.1) or (ipv6 and ipv6.SrcAddr != ::1))" + filter)
		}
	case false:
		{
			filter = ("outbound and tcp and tcp.SrcPort == 8080 and tcp.DstPort == 80" + filter)
		}
	}

	return filter
}

//////////////////////////////////////////////////////////
// func HandleNewTcpConnection(connInfo int, srcPort int16 isIpv6 bool)
// {
// 	if (connInfo != null && connInfo.OwnerPid == os.Getpid()) {
// 		// This is our process.
// 		if isIpv6 == true {
// 			v6ShouldFilter[srcPort] = true
// 		} else {

// 		}
// 		switch (isIpv6)
// 		{
// 			case true:
// 				{
// 					Volatile.Write(ref _v6ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
// 				}
// 				break;

// 			case false:
// 				{
// 					Volatile.Write(ref _v4ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
// 				}
// 				break;
// 		}
// 	}
// 	else
// 	{
// 		FirewallResponse response = null;
// 		if (connInfo == null || connInfo.OwnerPid == 4 || connInfo.OwnerPid == 0)
// 		{
// 			var firewallRequest = new FirewallRequest("SYSTEM", tcpHeader->SrcPort, tcpHeader->DstPort, connInfo.OwnerPid);
// 			response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
// 		}
// 		else
// 		{
// 			// No need to null check here, because the above IF catches whenever connInfo is null.
// 			var procPath = connInfo.OwnerProcessPath.Length > 0 ? connInfo.OwnerProcessPath : "SYSTEM";
// 			var firewallRequest = new FirewallRequest(procPath, tcpHeader->SrcPort, tcpHeader->DstPort, connInfo.OwnerPid);
// 			response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
// 		}

// 		if (response == null)
// 		{
// 			// The user couldn't be bothered to give us an answer, so just go ahead and let
// 			// the packet through.

// 			switch (isIpv6)
// 			{
// 				case true:
// 					{
// 						Volatile.Write(ref _v6ShouldFilter[tcpHeader->SrcPort], (byte)FirewallAction.DontFilterApplication);

// 						Volatile.Write(ref _v6EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == _httpsStandardPort || tcpHeader->DstPort == _httpsAltPort));
// 					}
// 					break;

// 				case false:
// 					{
// 						Volatile.Write(ref _v4ShouldFilter[tcpHeader->SrcPort], (byte)FirewallAction.DontFilterApplication);

// 						Volatile.Write(ref _v4EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == _httpsStandardPort || tcpHeader->DstPort == _httpsAltPort));
// 					}
// 					break;
// 			}
// 		}
// 		else
// 		{
// 			switch (isIpv6)
// 			{
// 				case true:
// 					{
// 						Volatile.Write(ref _v6ShouldFilter[tcpHeader->SrcPort], (byte)response.Action);

// 						Volatile.Write(ref _v6EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == _httpsStandardPort || tcpHeader->DstPort == _httpsAltPort));
// 					}
// 					break;

// 				case false:
// 					{
// 						Volatile.Write(ref _v4ShouldFilter[tcpHeader->SrcPort], (byte)response.Action);

// 						Volatile.Write(ref _v4EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == _httpsStandardPort || tcpHeader->DstPort == _httpsAltPort));
// 					}
// 					break;
// 			}
// 		}
// 	}
// }

///////////////////////////////////////////////////////////
func main() {
	tcpHelper, err := godivert.NewTCPHelper()
	if err != nil {
		panic(err)
	}
	defer tcpHelper.Close()
	ProxyPort := uint16(8080)
	//AltProxyPort := uint16(4443)
	//ProxyIP := net.ParseIP("127.0.0.1")
	var PortsArray [65536]uint16
	var v4ShouldFilter [65536]uint16

	//HTTPPort := uint16(80)
	// HTTPSPort := uint16(443)
	// filter := GenerateFilterString(false)
	// fmt.Println(filter)

	//filter := "tcp and ip and outbound and !loopback and !impostor and (tcp.DstPort == 80 or tcp.DstPort=443 or tcp.SrcPort == 8080)"
	filter := "tcp and outbound and !loopback and !impostor and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 8080)"
	//filter := "tcp and outbound"
	//fmt.Println(filter)
	winDivert, err := godivert.NewWinDivertHandle(filter, -1000, 0)
	if err != nil {
		panic(err)
	}
	udpDropFilter := "outbound and udp and (udp.DstPort == 80 || udp.DstPort == 443)"
	winDivertDropUDP, err2 := godivert.NewWinDivertHandle(udpDropFilter, -999, 2)
	if err2 != nil {
		panic(err2)
	}

	defer winDivert.Close()
	defer winDivertDropUDP.Close()
	for {
		packet, err1 := winDivert.Recv()
		if err1 != nil {
			panic(err1)
		}
		packet.VerifyParsed()
		ipVersion := packet.IpVersion()

		//		fmt.Println("PACKET", packet)

		srcPort, err1 := packet.SrcPort()
		if err1 != nil {
			packet.Send(winDivert)
			continue
		}

		srcIP := packet.SrcIP()
		if packet.Syn() != false {
			//fmt.Println("PACKET", packet.Syn())

			pid, err := tcpHelper.GetConnectionPID(int(srcPort), srcIP.String(), ipVersion)
			if err != nil {
				panic(err)
			}

			//fmt.Println("PID:", pid, srcPort)

			if pid == 16644 /*os.Getpid()*/ {
				v4ShouldFilter[srcPort] = 0
				fmt.Println("IT IS OUR PID", pid)
			} else {
				v4ShouldFilter[srcPort] = 1
			}
		}

		dstPort, err0 := packet.DstPort()
		if err0 != nil {
			packet.Send(winDivert)
			continue
		}
		dstIP := packet.DstIP()
		fmt.Println("DESTINATION IP", dstIP, dstPort)
		//fmt.Println("IS PRIVATE IP?", isPrivateIP(dstIP))

		// if packet.Direction() == true {
		// 	//fmt.Println("INBOUND:************", srcPort, dstPort, srcIP, dstIP)
		// 	// if srcPort == HTTPPort {
		// 	// 	packet.SetSrcPort(ProxyPort)
		// 	// }
		// 	packet.Send(winDivert)
		// 	continue
		// }

		if packet.Direction() == false {
			if srcPort == ProxyPort {
				fmt.Println("FROM PROXY:************", srcPort, dstPort, srcIP, dstIP, PortsArray[dstPort])
				packet.SetSrcPort(PortsArray[dstPort])
				packet.Addr.SetDirection(true)
				packet.SetDstIP(srcIP)
				packet.SetSrcIP(dstIP)
				packet.CalcNewChecksum(winDivert)
				//packet.Send(winDivert)
				//fmt.Println("WIND DIVERT ADDRESS", packet.Addr)
			} else {
				// Reflect: PORT ---> PROXY
				fmt.Println("TO PROXY:************", srcPort, dstPort, srcIP, dstIP)
				if v4ShouldFilter[srcPort] > 0 {
					packet.SetDstPort(ProxyPort)
					PortsArray[srcPort] = dstPort
					packet.SetDstIP(srcIP)
					packet.SetSrcIP(dstIP)
					packet.Addr.SetDirection(true)
					packet.CalcNewChecksum(winDivert)
					//packet.Send(winDivert)
					fmt.Println("WIND DIVERT ADDRESS", packet.Addr)
				}
			}
			//			fmt.Println("WIND DIVERT ADDRESS", packet.Addr)
			packet.Send(winDivert)
		}
		//packet.Send(winDivert)
	}
}
