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

#pragma once

#include <stdio.h>
#include <zeek/analyzer/protocol/tcp/TCP.h>
#include <zeek/analyzer/Analyzer.h>
#include <NetVar.h>
#include "Typedef.h"

namespace zeek::analyzer { namespace iso_over_tcp {

    class ISO_Over_TCP_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
        public:
            explicit ISO_Over_TCP_Analyzer(Connection* conn);
            ~ISO_Over_TCP_Analyzer();
            void Done();
            void Init();
            void DeliverStream(int len, const u_char* data, bool orig);
            
            static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
            {
                return new ISO_Over_TCP_Analyzer(conn);
            }
        protected:

            int offset;

            void parseTPKT(int len, int offset, const u_char* data, bool orig);
            void parseCOTP(int len, int offset, const u_char* data, bool orig);
    };

} } //end namespaces
