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
#include <algorithm>
#include <vector>
#include <analyzer/protocol/tcp/TCP.h>
#include <analyzer/Analyzer.h>
#include <NetVar.h>
#include <Typedef.h>

struct s7plus_header {
    u_char protocol_id;
    u_char version;
    u_int16 data_length;
};

struct s7plus_trailer {
    u_char protocol_id;
    u_char version;
    u_int16 data_length;
};

namespace zeek::analyzer { namespace s7_comm_plus {

    union real_to_float_union
    {
        unsigned long ul;
        float f;
    };

    class S7_Comm_Plus_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
        public:
            S7_Comm_Plus_Analyzer(Connection* conn);
            virtual ~S7_Comm_Plus_Analyzer();
            virtual void Done();
            virtual void Init();
            virtual void DeliverStream(int len, const u_char* data, bool orig);
            
            static analyzer::Analyzer* Instantiate(Connection* conn)
            {
                return new S7_Comm_Plus_Analyzer(conn);
            }
        protected:
            int offset;
            int data_offset;
            s7plus_header* ParseHeader(const u_char* data);
            s7plus_trailer* ParseTrailer(const u_char* data);

            void ParseData(const u_char* data, s7plus_header* header, s7plus_trailer* trailer);

            void ParseNotification(const u_char* data);

            void ParseGetMultiVariablesReq(const u_char* data);
            void ParseSetMultiVariablesReq(const u_char* data);
            void ParseSetVariableReq(const u_char* data);
            void ParseCreateObjectReq(const u_char* data);
            void ParseDeleteObjectReq(const u_char* data);
            void ParseGetVarSubStreamedReq(const u_char* data);
            void ParseExploreReq(const u_char* data);
            void ParseGetLinkReq(const u_char* data);
            void ParseBeginSequenceReq(const u_char* data);
            void ParseEndSequenceReq(const u_char* data);
            void ParseInvokeReq(const u_char* data);

            void ParseGetMultiVariablesRes(const u_char* data);
            void ParseSetMultiVariablesRes(const u_char* data);
            void ParseSetVariableRes(const u_char* data);
            void ParseCreateObjectRes(s7plus_header*, const u_char* data);
            void ParseDeleteObjectRes(const u_char* data);
            void ParseGetVarSubStreamedRes(const u_char* data);
            void ParseExploreRes(const u_char* data);
            void ParseGetLinkRes(const u_char* data);
            void ParseBeginSequenceRes(const u_char* data);
            void ParseEndSequenceRes(const u_char* data);
            void ParseInvokeRes(const u_char* data);

            void ParseAddressItem(const u_char* data, int function_code);

            std::string HexToString(const unsigned char* data, int length);
            std::string HexToASCII(const unsigned char* data, int length);
            std::string TimestampToString(uint64_t timestamp);
            std::string TimespanToString(uint64_t timespan);

            int GetVarUInt64(const unsigned char* data, int& octets);
            int GetVarInt64(const unsigned char* data, int& octets);
            int GetVarUInt32(const unsigned char* data, int& octets);
            int GetVarInt32(const unsigned char* data, int& octets);
            uint64_t ntoh64(const uint64_t input);

            void DecodeValue(const u_char* data, std::string context, bool first_value);
            void DecodeValueList(const u_char* data, std::string context);
            void DecodeRelation(const u_char* data, std::string context);
            void DecodeObject(const u_char* data, std::string context);
            void SkipToNextElementID(const u_char* data);
            float RealToFloat(std::string data);
    };

} 
} //end namespaces
