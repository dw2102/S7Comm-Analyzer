/**
 * ISO over TCP / S7Comm protocol analyzer.
 * 
 * Based on the Wireshark dissector written by Thomas Wiens 
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm.h
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm.c
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm_szl_ids.h
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm_szl_ids.c
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
 * Date: 02.06.2023
 * Version: 1.1
 * 
 * This plugin was a part of a master's thesis written at Fachhochschule in Aachen (Aachen University of Applied Sciences)
 * Rewritten for Zeek version 5.0.9
 */

#include "Plugin.h"
#include <iostream>

namespace plugin { namespace ICS_ISO_OVER_TCP { Plugin plugin; } }

using namespace plugin::ICS_ISO_OVER_TCP;

zeek::plugin::Configuration Plugin::Configure()
	{

	AddComponent(new zeek::analyzer::Component("Iso_Over_TCP", zeek::analyzer::iso_over_tcp::ISO_Over_TCP_Analyzer::Instantiate));

	AddComponent(new zeek::analyzer::Component("S7_Comm", zeek::analyzer::s7_comm::S7_Comm_Analyzer::Instantiate));
	
	AddComponent(new zeek::analyzer::Component("S7_Comm_Plus", zeek::analyzer::s7_comm_plus::S7_Comm_Plus_Analyzer::Instantiate));
	
	zeek::plugin::Configuration config;
	config.name = "ICS::S7Comm";
	config.description = "<ISO over TCP Protocol Analyzer to support the S7Comm and S7CommPlus protocol.";
	config.version.minor = 1;
	config.version.patch = 1;
	return config;
	}
