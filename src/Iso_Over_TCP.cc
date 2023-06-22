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

#include "Iso_Over_TCP.h"
#include "Event.h"
#include "events.bif.h"
#include "Iso_Over_TCP_Constant.h"
#include <zeek/analyzer/Manager.h>
#include "S7Comm.h"
#include "S7CommPlus.h"

using namespace zeek::analyzer::iso_over_tcp;

ISO_Over_TCP_Analyzer::ISO_Over_TCP_Analyzer(Connection* conn): analyzer::tcp::TCP_ApplicationAnalyzer("Iso_Over_TCP", conn)
{

}

ISO_Over_TCP_Analyzer::~ISO_Over_TCP_Analyzer()
{

}

void ISO_Over_TCP_Analyzer::Init()
{
    analyzer::tcp::TCP_ApplicationAnalyzer::Init();
    
}

void ISO_Over_TCP_Analyzer::Done()
{
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();
    
}

void ISO_Over_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    offset = 0;
    // First parse the TPKT packet...
    parseTPKT(len, offset, data, orig);
}

void ISO_Over_TCP_Analyzer::parseTPKT(int len, int offset, const u_char* data, bool orig)
{
    EventHandlerPtr ev;
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
    if (*version != 3)
    {
        Weird("Unexpected TPKT version detected");
    }

    if (ntohs(*length) != len)
    {
        Weird("Stream length doesn't match TPKT length");
        return;
    }
    ev = tpkt_packet;
    EnqueueConnEvent(ev, ConnVal(), val_mgr->Count(*version), val_mgr->Count(ntohs(*length)));

    // Now parse the COTP packet which is encapsulated in TPKT...
    parseCOTP(len, offset, data, orig);
}

void ISO_Over_TCP_Analyzer::parseCOTP(int len, int offset, const u_char* data, bool orig)
{
    EventHandlerPtr ev;

    // Field of the COTP packet..
    u_char* length;
    u_char* tpdu_type;
    u_char* tpdu_nr_eot;
    u_char* protocol_id;


    length = (u_char*) (data + offset);
    offset += 1;
    tpdu_type = (u_char*) (data + offset);
    offset += 1;

    // Create new COTP packet event... 

    ev = cotp_packet;
    EnqueueConnEvent(ev, ConnVal(), val_mgr->Count(*tpdu_type));

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
                    Analyzer* s7comm = s7_comm::S7_Comm_Analyzer::Instantiate(Conn());
                    AddChildAnalyzer(s7comm);                        

                    // Forward the rest of the stream to the S7Comm analyzer...
                    ForwardStream(len, (data + offset), orig);
                    break;
                }
                case PROTOCOL_S7_COMM_PLUS:
                {
                    Analyzer* s7commplus = s7_comm_plus::S7_Comm_Plus_Analyzer::Instantiate(Conn());
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