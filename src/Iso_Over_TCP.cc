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

#include "Iso_Over_TCP.h"
#include "S7Comm.h"
#include "S7CommPlus.h"
#include "Event.h"
#include "S7Comm_Constants.h"
#include "events.bif.h"
#include "types.bif.h"

using namespace analyzer::Iso_Over_TCP;

ISO_Over_TCP_Analyzer::ISO_Over_TCP_Analyzer(Connection* conn): tcp::TCP_ApplicationAnalyzer("Iso_Over_TCP", conn)
{

}

ISO_Over_TCP_Analyzer::~ISO_Over_TCP_Analyzer()
{

}

void ISO_Over_TCP_Analyzer::Init()
{
    tcp::TCP_ApplicationAnalyzer::Init();
}

void ISO_Over_TCP_Analyzer::Done()
{
    tcp::TCP_ApplicationAnalyzer::Done();
}

void ISO_Over_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    offset = 0;
    // First parse the TPKT packet...
    parseTPKT(len, offset, data, orig);
}

void ISO_Over_TCP_Analyzer::parseTPKT(int len, int offset, const u_char* data, bool orig)
{
    // Event variables
    EventHandlerPtr ev;
    val_list* vl;
    // Field of the TPKT packet...
    u_char* version; // should be 3
    u_char* reserved; //most of the times 0
    u_int16* length; //big endian

    // Map the 4 byte...
    version = (u_char*)(data);
    offset += 1;

    reserved = (u_char*) (data+offset);
    offset += 1;

    length = (u_int16*) (data+offset);
    offset += 2;

    // Check if TPKT version equals 3...
    if(*version != 3)
    {
        Weird("Unexpected TPKT version detected");
    }

    if(ntohs(*length) != len)
    {
        Weird("Stream length doesn't match TPKT length");
        return;
    }

    // Create new TPKT packet event...
    vl = new val_list();
    vl->append(BuildConnVal());
    vl->append(new Val(*version, TYPE_COUNT));
    vl->append(new Val(ntohs(*length), TYPE_COUNT));
    ev = tpkt_packet;

    ConnectionEvent(ev, vl);

    // Now parse the COTP packet which is encapsulated in TPKT...
    parseCOTP(len, offset, data, orig);

}

void ISO_Over_TCP_Analyzer::parseCOTP(int len, int offset, const u_char* data, bool orig)
{
    EventHandlerPtr ev;
    val_list* vl;

    // Field of the COTP packet..
    u_char* length;
    u_char* tpdu_type;
    u_char* tpdu_nr_eot;
    u_char* protocol_id;


    length = (u_char*) (data+offset);
    offset += 1;
    tpdu_type = (u_char*) (data+offset);
    offset += 1;

    // Create new COTP packet event... 
    vl = new val_list();
    vl->append(BuildConnVal());
    vl->append(new Val(*tpdu_type, TYPE_COUNT));
    ev = cotp_packet;

    ConnectionEvent(ev, vl);

    switch (*tpdu_type & 0xF0) // we only need the first 4 bit for now...
    {
        case CR:    // Connection Request
        {
            break;
        } 
        case CC:    // Connection Confirm
        {
            break;
        }   
        case RJ:    // Reject
        {
            break;
        }               
        case AK:    // Data Acknowledge
        {
            break;
        } 
        case DR:    // Disconnect Request
        {
            break;
        } 
        case DC:    // Disconnect Confirm
        {
            break;
        } 
        case DT:    // Data TPDU -> used by S7Comm & S7CommPlus
        {
            tpdu_nr_eot = (u_char*) (data + offset);
            offset += 1;
            protocol_id = (u_char*) (data + offset);

            // Lookahead to S7 protocol id
            switch ((short)*protocol_id)
            {
                case PROTOCOL_S7_COMM:
                {
                    Analyzer* s7comm = S7_Comm::S7_Comm_Analyzer::Instantiate(Conn());
                    AddChildAnalyzer(s7comm);                        

                    // Forward the rest of the stream to the S7Comm analyzer...
                    ForwardStream(len, (data + offset), orig);
                    break;
                }
                case PROTOCOL_S7_COMM_PLUS:
                {
                    Analyzer* s7commplus = S7_Comm_Plus::S7_Comm_Plus_Analyzer::Instantiate(Conn());
                    AddChildAnalyzer(s7commplus);                        

                    // Forward the rest of the stream to the S7CommPlus analyzer...
                    ForwardStream(len, (data + offset), orig);
                    break;
                }
            }
            break;
        } 
        case ED:    // Expedited Data
        {
            break;
        } 
        case EA:    // Expedited Data Acknowledge
        {
            break;
        } 
        case ERR:   // Error PDU
        {
            break;
        } 
    }
}

