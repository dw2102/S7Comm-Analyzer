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

#ifndef ANALYZER_PROTOCOLS7_COMM_H
#define ANALYZER_PROTOCOLS7_COMM_H

#include <stdio.h>
#include <algorithm>
#include <vector>
#include <analyzer/protocol/tcp/TCP.h>
#include <analyzer/Analyzer.h>
#include <NetVar.h>

typedef unsigned char u_char;
typedef unsigned short u_int16;
typedef short int16;
typedef unsigned int u_int32;
typedef int int32;
typedef uint64_t u_int64;
typedef int64_t int64;

struct s7_header {
    u_char protocol_id;
    u_char msg_type;
    u_int16 reserved;
    u_int16 pdu_ref;
    u_int16 parameter_length;
    u_int16 data_length;
    u_char error_class;
    u_char error_code;
};

/*
 * Copied from https://github.com/wireshark/wireshark/blob/5d99febe66e96b55a1defa58a906be254bad3a51/epan/dissectors/packet-s7comm.c 
 * Enumeration of all possible PI serivces followed by vector of string (originally array of string_string)
*/
typedef enum
{
    S7COMM_PI_UNKNOWN = 0,
    S7COMM_PI_INSE,
    S7COMM_PI_DELE,
    S7COMM_PIP_PROGRAM,
    S7COMM_PI_MODU,
    S7COMM_PI_GARB,
    S7COMM_PI_N_LOGIN_,
    S7COMM_PI_N_LOGOUT,
    S7COMM_PI_N_CANCEL,
    S7COMM_PI_N_DASAVE,
    S7COMM_PI_N_DIGIOF,
    S7COMM_PI_N_DIGION,
    S7COMM_PI_N_DZERO_,
    S7COMM_PI_N_ENDEXT,
    S7COMM_PI_N_F_OPER,
    S7COMM_PI_N_OST_OF,
    S7COMM_PI_N_OST_ON,
    S7COMM_PI_N_SCALE_,
    S7COMM_PI_N_SETUFR,
    S7COMM_PI_N_STRTLK,
    S7COMM_PI_N_STRTUL,
    S7COMM_PI_N_TMRASS,
    S7COMM_PI_N_F_DELE,
    S7COMM_PI_N_EXTERN,
    S7COMM_PI_N_EXTMOD,
    S7COMM_PI_N_F_DELR,
    S7COMM_PI_N_F_XFER,
    S7COMM_PI_N_LOCKE_,
    S7COMM_PI_N_SELECT,
    S7COMM_PI_N_SRTEXT,
    S7COMM_PI_N_F_CLOS,
    S7COMM_PI_N_F_OPEN,
    S7COMM_PI_N_F_SEEK,
    S7COMM_PI_N_ASUP__,
    S7COMM_PI_N_CHEKDM,
    S7COMM_PI_N_CHKDNO,
    S7COMM_PI_N_CONFIG,
    S7COMM_PI_N_CRCEDN,
    S7COMM_PI_N_DELECE,
    S7COMM_PI_N_CREACE,
    S7COMM_PI_N_CREATO,
    S7COMM_PI_N_DELETO,
    S7COMM_PI_N_CRTOCE,
    S7COMM_PI_N_DELVAR,
    S7COMM_PI_N_F_COPY,
    S7COMM_PI_N_F_DMDA,
    S7COMM_PI_N_F_PROT,
    S7COMM_PI_N_F_RENA,
    S7COMM_PI_N_FINDBL,
    S7COMM_PI_N_IBN_SS,
    S7COMM_PI_N_MMCSEM,
    S7COMM_PI_N_NCKMOD,
    S7COMM_PI_N_NEWPWD,
    S7COMM_PI_N_SEL_BL,
    S7COMM_PI_N_SETTST,
    S7COMM_PI_N_TMAWCO,
    S7COMM_PI_N_TMCRTC,
    S7COMM_PI_N_TMCRTO,
    S7COMM_PI_N_TMFDPL,
    S7COMM_PI_N_TMFPBP,
    S7COMM_PI_N_TMGETT,
    S7COMM_PI_N_TMMVTL,
    S7COMM_PI_N_TMPCIT,
    S7COMM_PI_N_TMPOSM,
    S7COMM_PI_N_TRESMO,
    S7COMM_PI_N_TSEARC
} pi_service_e;

static const std::vector<std::string> pi_service_names = {
    "UNKNOWN", "_INSE", "_DELE", "P_PROGRAM", "_MODU", "_GARB","_N_LOGIN_", "_N_LOGOUT", "_N_CANCEL", "_N_DASAVE", "_N_DIGIOF", "_N_DIGION", "_N_DZERO_",                       
    "_N_ENDEXT", "_N_F_OPER", "_N_OST_OF", "_N_OST_ON", "_N_SCALE_", "_N_SETUFR", "_N_STRTLK", "_N_STRTUL", "_N_TMRASS", "_N_F_DELE", "_N_EXTERN", "_N_EXTMOD",                      
    "_N_F_DELR", "_N_F_XFER", "_N_LOCKE_", "_N_SELECT", "_N_SRTEXT", "_N_F_CLOS", "_N_F_OPEN", "_N_F_SEEK", "_N_ASUP__", "_N_CHEKDM", "_N_CHKDNO", "_N_CONFIG",                     
    "_N_CRCEDN", "_N_DELECE", "_N_CREACE", "_N_CREATO", "_N_DELETO", "_N_CRTOCE", "_N_DELVAR", "_N_F_COPY", "_N_F_DMDA", "_N_F_PROT", "_N_F_RENA", "_N_FINDBL",                          
    "_N_IBN_SS", "_N_MMCSEM", "_N_NCKMOD", "_N_NEWPWD", "_N_SEL_BL", "_N_SETTST", "_N_TMAWCO", "_N_TMCRTC", "_N_TMCRTO", "_N_TMFDPL", "_N_TMFPBP", "_N_TMGETT",                         
    "_N_TMMVTL", "_N_TMPCIT", "_N_TMPOSM", "_N_TRESMO", "_N_TSEARC"
};

namespace analyzer { namespace S7_Comm {

    union real_to_float_union
    {
        unsigned long ul;
        float f;
    };

    class S7_Comm_Analyzer : public tcp::TCP_ApplicationAnalyzer {
        public:
            S7_Comm_Analyzer(Connection* conn);
            virtual ~S7_Comm_Analyzer();
            virtual void Done();
            virtual void Init();
            virtual void DeliverStream(int len, const u_char* data, bool orig);
            
            static analyzer::Analyzer* Instantiate(Connection* conn)
            {
                return new S7_Comm_Analyzer(conn);
            }
        protected:
            int offset;

            void ParseHeader(int len, const u_char* data, bool orig);
            void ParseParameter(int len, const u_char* data, s7_header* header, bool orig);
            void ParseUDParameter(s7_header* header, int len, const u_char* data, bool orig);

            // Regular functions
            void ParseAck(s7_header* header);
            void ParseCpuService(s7_header* header, const u_char* data); // seems to be optional because no have no useful data about this function
            void ParseSetupCommunication(s7_header* header, const u_char* data);
            void ParseReadVariable(s7_header* header, const u_char* data);
            void ParseWriteVariable(s7_header* header, const u_char* data);

            void ParseStartUpload(s7_header* header, const u_char* data);
            void ParseUpload(s7_header* header, const u_char* data);
            void ParseEndUpload(s7_header* header, const u_char* data);

            void ParseRequestDownload(s7_header* header, const u_char* data);
            void ParseDownloadBlock(s7_header* header, const u_char* data);
            void ParseDownloadEnded(s7_header* header, const u_char* data);

            void ParsePLCControl(s7_header* header, const u_char* data);
            int GetPIServiceIndex(std::string plc_service_name);
            void DecodePLCControlParameter(const u_char* data, int param_offset, int fields, VectorVal* &strings_vec);
            void ParsePLCStop(s7_header* header, const u_char* data);

            RecordVal* ParseAnyItem(const u_char* data);
            RecordVal* ParseDbItem(const u_char* data);
            RecordVal* ParseSymItem(const u_char* data);
            RecordVal* ParseNckItem(const u_char* data);
            RecordVal* ParseDriveAnyItem(const u_char* data);

            RecordVal* ParseReadWriteData(const u_char* data, short item_count);
            short ParseAckDataWriteData(const u_char* data);

            RecordVal* ParseAckDataDownloadData(const u_char* data);

            RecordVal* CreateHeader(s7_header* header);
            RecordVal* CreateHeaderWithError(s7_header* header);

            // UserData functions
            void ParseUDProgSubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDCyclSubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDBlockSubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDCPUSubfunction(s7_header* header, const u_char* data, short subfunction, short data_ref_num, bool last_data, short type);
            void ParseUDSecuritySubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDPBCSubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDTimeSubfunction(s7_header* header, const u_char* data, short subfunction, short type);
            void ParseUDNCProgSubfunction(s7_header* header, const u_char* data, short subfunction, short type);

            RecordVal* ParseUDUnknownData(const u_char* data);
            RecordVal* ParseUDReqDiagData(short subfunction, const u_char* data);
            RecordVal* ParseUDProgUnknownData(short subfunction, const u_char* data);
            RecordVal* ParseUDVarTab1Request(short subfunction, const u_char* data);
            RecordVal* ParseUDVarTab1Response(short subfunction, const u_char* data);

            void ParseUDCyclMem(s7_header* header, std::string packet_type, short subfunction, const u_char* data);
            void ParseUDCyclMemAck(s7_header* header, std::string packet_type, short subfunction, const u_char* data);

            RecordVal* ParseUDBlockListType(short subfunction, const u_char* data);
            RecordVal* ParseUDBlockBlockInfoReq(short subfunction, const u_char* data);
            RecordVal* ParseUDBlockBlockInfoRes(short subfunction, const u_char* data);


            RecordVal* ParseS7Time(const u_char* data);

            std::string HexToString(const unsigned char* data, int length);
            std::string HexToASCII(const unsigned char* data, int length);
            std::string GetPacketType(short type);
            std::string TimestampToString(const u_char* data);
            std::string S7TimeStampToString(const u_char* data, short bytes);
            float RealToFloat(std::string data);
            
    };

} } //end namespaces


#endif