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

#ifndef ANALYZER_PROTOCOL_ISO_OVER_TCP_H
#define ANALYZER_PROTOCOL_ISO_OVER_TCP_H

#include <stdio.h>
#include <analyzer/protocol/tcp/TCP.h>
#include <analyzer/Analyzer.h>
#include <NetVar.h>

typedef unsigned char u_char;
typedef unsigned short u_int16;
typedef short int16;
typedef unsigned int u_int32;
typedef int int32;

namespace analyzer { namespace Iso_Over_TCP {

    class ISO_Over_TCP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
        public:
            ISO_Over_TCP_Analyzer(Connection* conn);
            virtual ~ISO_Over_TCP_Analyzer();
            virtual void Done();
            virtual void Init();
            virtual void DeliverStream(int len, const u_char* data, bool orig);
            
            static analyzer::Analyzer* Instantiate(Connection* conn)
            {
                return new ISO_Over_TCP_Analyzer(conn);
            }
        protected:

            int offset;

            void parseTPKT(int len, int offset, const u_char* data, bool orig);
            void parseCOTP(int len, int offset, const u_char* data, bool orig);
    };

} } //end namespaces


#endif