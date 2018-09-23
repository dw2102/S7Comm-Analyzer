/**
 * ISO over TCP / S7Comm protocol analyzer.
 * 
 * Based on the Wireshark dissector written by Thomas Wiens 
 * https://github.com/wireshark/wireshark/blob/5d99febe66e96b55a1defa58a906be254bad3a51/epan/dissectors/packet-s7comm.c,
 * https://github.com/wireshark/wireshark/blob/5d99febe66e96b55a1defa58a906be254bad3a51/epan/dissectors/packet-s7comm.h,
 * https://github.com/wireshark/wireshark/blob/fe219637a6748130266a0b0278166046e60a2d68/epan/dissectors/packet-s7comm_szl_ids.h,
 * https://github.com/wireshark/wireshark/blob/fe219637a6748130266a0b0278166046e60a2d68/epan/dissectors/packet-s7comm_szl_ids.c,
 * https://sourceforge.net/projects/s7commwireshark/
 * 
 * partially on the PoC S7Comm-Bro-Plugin written by György Miru
 * https://github.com/CrySyS/bro-step7-plugin/blob/master/README.md,
 * 
 * RFC 1006 (ISO Transport Service on top of the TCP)
 * https://tools.ietf.org/html/rfc1006
 * 
 * and RFC 905 (ISO Transport Protocol Specification)
 * https://tools.ietf.org/html/rfc0905
 * 
 * Author: Dane Wullen
 * Date: 10.04.2018
 * Version: 1.0
 * 
 * This plugin is a part of a master's thesis written at Fachhochschule in Aachen (Aachen University of Applied Sciences)
 * 
 */

#include "Plugin.h"
#include "Iso_Over_TCP.h"
#include "S7Comm.h"
#include "S7CommPlus.h"

namespace plugin { namespace Bro_Iso_Over_TCP { Plugin plugin; } }

using namespace plugin::Bro_Iso_Over_TCP;

plugin::Configuration Plugin::Configure()
	{
		// "Main" analyzer to parse  TPKT packets which encapsulates COTP and the S7 protocol
		AddComponent(new ::analyzer::Component("Iso_Over_TCP", ::analyzer::Iso_Over_TCP::ISO_Over_TCP_Analyzer::Instantiate));
		// "Support like" analyzer, which covers the s7comm packets
		AddComponent(new ::analyzer::Component("S7_Comm", ::analyzer::S7_Comm::S7_Comm_Analyzer::Instantiate));
		// "Support like" analyzer which covers the s7commplus packets
		AddComponent(new ::analyzer::Component("S7_Comm_Plus", ::analyzer::S7_Comm_Plus::S7_Comm_Plus_Analyzer::Instantiate));


		plugin::Configuration config;
		config.name = "Bro::Iso_Over_TCP";
		config.description = "<ISO over TCP Protocol Analyzer to support the S7Comm and S7CommPlus protocol. Based on the Wireshark dissector written by Thomas Wiens and partially on the PoC-S7Comm-Plugin written by György Miru.>";
		config.version.major = 1;
		config.version.minor = 0;
		return config;
	}
