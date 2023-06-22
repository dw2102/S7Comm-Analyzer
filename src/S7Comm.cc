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

#include <vector>
#include <sstream>
#include <time.h>
#include "S7Comm.h"
#include "Event.h"
#include "S7Comm_Constants.h"
#include "events.bif.h"
#include "types.bif.h"

#include <iostream>

using namespace zeek::analyzer::s7_comm;

S7_Comm_Analyzer::S7_Comm_Analyzer(Connection* conn): tcp::TCP_ApplicationAnalyzer("S7_Comm", conn)
{

}

S7_Comm_Analyzer::~S7_Comm_Analyzer()
{

}

void S7_Comm_Analyzer::Init()
{
    tcp::TCP_ApplicationAnalyzer::Init();
}

void S7_Comm_Analyzer::Done()
{
    tcp::TCP_ApplicationAnalyzer::Done();
}

void S7_Comm_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    offset = 0;
    // The S7 packet is divided in 3 parts: header, parameter, data.
    // We need to dissect them step by step, depending of the MSG Type
    // and functions

    // First the header...
    ParseHeader(len, data, orig);
}

void S7_Comm_Analyzer::ParseHeader(int len, const u_char* data, bool orig)
{
    s7_header* header;

    header = (s7_header*)(data+offset);
    offset += 10;

    if(len < S7COMM_MIN_TELEGRAM_LENGTH) //Equals min. Header size
    {
        Weird("S7Comm: Packet is too short");
        return;
    }
    
    // 4 different MSG-Types
    switch (header->msg_type)
    {
        case S7COMM_ROSCTR_JOB:
        {
            ParseParameter(len, data, header, orig);
            break;
        }
        case S7COMM_ROSCTR_USERDATA:
        {
            ParseUDParameter(header, len, data, orig);
            break;
        }
        case S7COMM_ROSCTR_ACK:
        {
            ParseAck(header);
            break;
        }
        case S7COMM_ROSCTR_ACK_DATA:
        {
            // Error fields are used by ACK and ACK_Data
            // increase offset
            offset += 2;

            ParseParameter(len, data, header, orig);
            break;
        }
        default:
        {
            Weird("Unsupported type detected!");
            return;
        }
    }
}

void S7_Comm_Analyzer::ParseParameter(int len, const u_char* data, s7_header* header, bool orig)
{
    u_char* function_code;

    function_code = (u_char*) (data + offset);
    offset += 1;

    switch(*function_code)
    {
        case S7COMM_CPU_SERVICE:
        {
            ParseCpuService(header, data);
            break;
        }
        case S7COMM_SETUP_COMMUNICATION:
        {
            ParseSetupCommunication(header, data);
            break;
        }
        case S7COMM_READ_VARIABLE:
        {
            ParseReadVariable(header, data);
            break;
        }
        case S7COMM_WRITE_VARIABLE:
        {
            ParseWriteVariable(header, data);
            break;
        }
        case S7COMM_REQUEST_DOWNLOAD:
        {
            ParseRequestDownload(header, data);
            break;
        }
        case S7COMM_DOWNLOAD_BLOCK:
        {
            ParseDownloadBlock(header, data);
            break;
        }
        case S7COMM_DOWNLOAD_ENDED:
        {
            ParseDownloadEnded(header, data);
            break;
        }
        case S7COMM_START_UPLOAD:
        {
            ParseStartUpload(header, data);
            break;
        }
        case S7COMM_UPLOAD:
        {
            ParseUpload(header, data);
            break;
        }
        case S7COMM_END_UPLOAD:
        {
            ParseEndUpload(header, data);
            break;
        }
        case S7COMM_PLC_CONTROL:
        {
            ParsePLCControl(header, data);
            break;
        }
        case S7COMM_PLC_STOP:
        {
            ParsePLCStop(header, data);
            break;
        }
    }
}

void S7_Comm_Analyzer::ParseAck(s7_header* header)
{
    Args vl;
    EventHandlerPtr ev = s7_ack;
    IntrusivePtr v1{AdoptRef{}, CreateHeader(header)};
    vl.emplace_back(ConnVal());
    vl.emplace_back(v1);
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseCpuService(s7_header* header, const u_char* data)
{
    Args vl;
    EventHandlerPtr ev = s7_cpu_service;
    IntrusivePtr v1{AdoptRef{}, CreateHeader(header)};
    vl.emplace_back(ConnVal());
    vl.emplace_back(v1);
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseSetupCommunication(s7_header* header, const u_char* data)
{
    // Parameter fields of Setup Communication 
    u_char* reserved;
    u_int16* max_amq_calling;
    u_int16* max_amq_caller;
    u_int16* pdu_length;
    Args vl;
    EventHandlerPtr ev;

    // Map everything over the data, increment offset...
    reserved = (u_char*)(data);
    offset += 1;
    max_amq_calling = (u_int16*)(data+offset);
    offset += 2;
    max_amq_caller = (u_int16*)(data+offset);
    offset += 2;
    pdu_length = (u_int16*)(data+offset);
    offset += 2;

    vl.emplace_back(ConnVal());

    // Set EventHandlerPtr to specific setup communication event
    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        ev = s7_job_setup_communication;
        IntrusivePtr v1{AdoptRef{}, CreateHeader(header)};
        vl.emplace_back(v1);
    }
    else if (header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        ev = s7_ackdata_setup_communication;
        IntrusivePtr v1{AdoptRef{}, CreateHeaderWithError(header)};
        vl.emplace_back(v1);
    }
    else 
    {
        Weird("Unexpected MSG Type for S7 setup communication");
        return;
    }

    // Create new RecordVal "S7SetupCommParam"
    RecordVal* rl = new RecordVal(BifType::Record::S7Comm::S7SetupCommParam);
    rl->Assign(0, val_mgr->Count(ntohs(*max_amq_calling)));
    rl->Assign(1, val_mgr->Count(ntohs(*max_amq_caller)));
    rl->Assign(2, val_mgr->Count(ntohs(*pdu_length)));

    // Append RecordVal
    IntrusivePtr v2{AdoptRef{}, rl};
    vl.emplace_back(v2);

    // Trigger event
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseReadVariable(s7_header* header, const u_char* data)
{
    /* Parameter item count*/
    u_char* item_count;
    /* Lookahead variables */
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;

    /*  Event variables */
    EventHandlerPtr ev;
    Args vl;
    RecordVal* item;

    /* To calculate the length of the packet*/ 
    int old_offset, len;
    item_count = (u_char*) (data + offset);
    offset += 1;

    // Save offset to determine if we need a "filling byte"
    old_offset = offset;

    // MSG-Type Job carries data in parameter field but doesn't have any date in data-field
    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        for(int i = 0; i < (short)*item_count; i++)
        {
            // Lookahead the first 3 bytes of the item to determine
            // which method is used without modifying the offset
            var_spec_typ = (u_char*) (data+offset);
            addr_length = (u_char*) (data+offset+1);
            syntax_id = (u_char*) (data+offset+2);

            if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_S7ANY)
            {
                // item = make_intrusive<RecordVal>(BifType::Record::S7Comm::S7AnyTypeItem);
                item = ParseAnyItem(data);
                ev = s7_job_read_variable_any_type;
            }
            else if(*var_spec_typ == 0x12 && *addr_length >= 7 && *syntax_id == S7COMM_SYNTAXID_DBREAD)
            {
                // item = make_intrusive<RecordVal>(BifType::Record::S7Comm::S7DBTypeItem);
                item = ParseDbItem(data);
                ev = s7_job_read_variable_db_type;
            }
            else if(*var_spec_typ == 0x12 && *addr_length >= 14 && *syntax_id == S7COMM_SYNTAXID_1200SYM)
            {
                // item = make_intrusive<RecordVal>(BifType::Record::S7Comm::S71200SymTypeItem);
                item = ParseSymItem(data);
                ev = s7_job_read_variable_1200_sym_type;
            }
            else if(*var_spec_typ == 0x12 && *addr_length == 8 && *syntax_id == S7COMM_SYNTAXID_NCK)
            {
                // item = make_intrusive<RecordVal>(BifType::Record::S7Comm::S7NCKTypeItem);
                item = ParseNckItem(data);
                ev = s7_job_read_variable_nck_type;
            }
            else if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
            {
                // item = make_intrusive<RecordVal>(BifType::Record::S7Comm::S7DriveAnyTypeItem);
                item = ParseDriveAnyItem(data);
                ev = s7_job_read_variable_drive_any_type;
            }
            else
            {
                Weird("S7_Job_Read: Unsupported variable specification...");
                // Skip this packet
                offset += (short)*addr_length + 2;
                len = offset - old_offset;
                // If len is not a multiplier by 2 and this is not the last item, put 
                // in a filling byte -> See Wireshark-dissector
                if((len % 2) && (i < (short)*item_count-1))
                {
                    offset += 1;
                }
                continue;
            }
            
            vl.emplace_back(ConnVal());
            vl.emplace_back(IntrusivePtr {AdoptRef{}, CreateHeader(header)});
            vl.emplace_back(val_mgr->Count((short)*item_count));
            vl.emplace_back(val_mgr->Count(i+1));
            vl.emplace_back(IntrusivePtr {AdoptRef{}, item});

            EnqueueConnEvent(ev, std::move(vl));

            len = offset - old_offset;
            // If len is not a multiplier by 2 and this is not the last item, put 
            // in a filling byte -> See Wireshark-dissector
            if((len % 2) && (i < (short)*item_count-1))
            {
                offset += 1;
            }
        }
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        // Except of item count, there should be no other 
        // field in the parameter section, so directly parse
        // the data field

        bool isNCK = false;

        for(int i = 0; i < (short)*item_count; i++)
        {
            item = ParseReadWriteData(data, (short)*item_count-i);

            if(item->GetType() == BifType::Record::S7Comm::S7NCKTypeItem)
            {
                ev = s7_ackdata_read_data_nck;  
            }
            else
            {
                ev = s7_ackdata_read_data;
            }

            vl.emplace_back(ConnVal());
            vl.emplace_back(IntrusivePtr {AdoptRef{}, CreateHeaderWithError(header)});
            vl.emplace_back(val_mgr->Count((short)*item_count));
            vl.emplace_back(val_mgr->Count(i+1));
            vl.emplace_back(IntrusivePtr {AdoptRef{}, item});
            EnqueueConnEvent(ev, std::move(vl));
        }
    }
}

void S7_Comm_Analyzer::ParseWriteVariable(s7_header* header, const u_char* data)
{
     /* Parameter item count*/
    u_char* item_count;

    /* Lookahead variables */
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;

    /*  Event variables */
    EventHandlerPtr ev;
    Args vl;
    std::vector<RecordVal*> item_vec;
    RecordVal* data_item;

    /* To calculate the length of the packet*/ 
    int old_offset, len;
   
    item_count = (u_char*) (data+offset);
    offset += 1;

    // Save offset to determine if we need a "filling byte"
    old_offset = offset;

    // MSG-Type Job carries data in parameter field but doesn't have any date in data-field
    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        for(int i = 0; i < (short)*item_count; i++)
        {
            // Lookahead the first 3 bytes of the item to determine
            // which method is used without modifying the offset
            var_spec_typ = (u_char*) (data+offset);
            addr_length = (u_char*) (data+offset+1);
            syntax_id = (u_char*) (data+offset+2);

            if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_S7ANY)
            {
                item_vec.push_back(ParseAnyItem(data));
            }
            else if(*var_spec_typ == 0x12 && *addr_length >= 7 && *syntax_id == S7COMM_SYNTAXID_DBREAD)
            {
                item_vec.push_back(ParseDbItem(data));
            }
            else if(*var_spec_typ == 0x12 && *addr_length >= 14 && *syntax_id == S7COMM_SYNTAXID_1200SYM)
            {
                item_vec.push_back(ParseSymItem(data));
            }
            else if(*var_spec_typ == 0x12 && *addr_length == 8 && *syntax_id == S7COMM_SYNTAXID_NCK)
            {
                item_vec.push_back(ParseNckItem(data));
            }
            else if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
            {
                item_vec.push_back(ParseDriveAnyItem(data));
            }
            else
            {
                Weird("S7_Job_Read: Unsupported variable specification...");
                // Dummy, we can skip afterwards
                item_vec.push_back(NULL);
                // Skip this packet
                offset += (short)*addr_length + 2;
                len = offset - old_offset;
                // If len is not a multiplier by 2 and this is not the last item, put 
                // in a filling byte -> See Wireshark-dissector
                if((len % 2) && (i < (short)*item_count-1))
                {
                    offset += 1;
                }
                // Skip this item...
                continue;
            }
            
            len = offset - old_offset;
            // If len is not a multiplier by 2 and this is not the last item, put 
            // in a filling byte -> See Wireshark-dissector
            if((len % 2) && (i < (short)*item_count-1))
            {
                offset += 1;
            }
        }
        // Now parse the data section and merge it
        for(int i = 0; i < (short)*item_count; i++)
        {
            data_item = ParseReadWriteData(data,(short)*item_count-1);

            if(item_vec[i] != NULL && item_vec[i]->GetType() == BifType::Record::S7Comm::S7AnyTypeItem)
            {
                ev = s7_job_write_variable_any_type;
            }
            else if(item_vec[i] != NULL && item_vec[i]->GetType() == BifType::Record::S7Comm::S7DBTypeItem)
            {
                ev = s7_job_write_variable_db_type;
            }
            else if(item_vec[i] != NULL && item_vec[i]->GetType() == BifType::Record::S7Comm::S71200SymTypeItem)
            {
                ev = s7_job_write_variable_1200_sym_type;
            }
            else if(item_vec[i] != NULL && item_vec[i]->GetType() == BifType::Record::S7Comm::S7NCKTypeItem)
            {
                ev = s7_job_write_variable_nck_type;
            }
            else if(item_vec[i] != NULL && item_vec[i]->GetType() == BifType::Record::S7Comm::S7DriveAnyTypeItem)
            {
                ev = s7_job_write_variable_drive_any_type;
            }
            else
            {
                // Skip this data because of unknown spec_type
                continue;
            }

            vl.emplace_back((ConnVal()));
            vl.emplace_back(IntrusivePtr {AdoptRef{}, CreateHeader(header)});
            vl.emplace_back(val_mgr->Count((short)*item_count));
            vl.emplace_back(val_mgr->Count(i+1));
            vl.emplace_back(IntrusivePtr {AdoptRef{}, item_vec[i]});
            vl.emplace_back(IntrusivePtr {AdoptRef{}, data_item});
            EnqueueConnEvent(ev, std::move(vl));
        }
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        ev = s7_ackdata_write_data;
        for(int i = 0; i < (short)*item_count; i++)
        {
            vl.emplace_back((ConnVal()));
            vl.emplace_back(IntrusivePtr {AdoptRef{}, CreateHeaderWithError(header)});
            vl.emplace_back(val_mgr->Count((short)*item_count));
            vl.emplace_back(val_mgr->Count(i+1));
            vl.emplace_back(val_mgr->Count(ParseAckDataWriteData(data)));
            EnqueueConnEvent(ev, std::move(vl));
        }
    }
}

void S7_Comm_Analyzer::ParseStartUpload(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_int32* upload_id;
    u_char* blockstring_length;
    u_char* filename_length;
    std::string filename;
    std::string blockstring;

    /*  Event variables */
    RecordVal* item;
    EventHandlerPtr ev;
    Args vl;

    func_status = (u_char*) (data+offset);
    offset += 3; // 1 + skip 2 unknown bytes
    upload_id = (u_int32*) (data+offset);
    offset += 4;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        filename_length = (u_char*) (data+offset);
        offset += 1;
        filename = HexToASCII((data + offset), (short)*filename_length);
        offset += (short)*filename_length;

        item = new RecordVal(BifType::Record::S7Comm::S7JobStartUpload);
        item->Assign(0, val_mgr->Count((short)*func_status));
        item->Assign(1, val_mgr->Count(ntohl(*upload_id)));
        item->Assign(2, val_mgr->Count((short)*filename_length));
        item->Assign(3, new StringVal(filename));

        ev = s7_job_start_upload;
        
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        blockstring_length = (u_char*) (data + offset);
        offset += 1;
        blockstring = HexToASCII((data+offset), (short)*blockstring_length);
        offset += (short)*blockstring_length;

        item = new RecordVal(BifType::Record::S7Comm::S7AckDataStartUpload);
        item->Assign(0, val_mgr->Count((short)*func_status));
        item->Assign(1, val_mgr->Count(ntohl(*upload_id)));
        item->Assign(2, val_mgr->Count((short)*blockstring_length));
        item->Assign(3, new StringVal(blockstring));

        ev = s7_ackdata_start_upload;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUpload(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_int32* upload_id;
    u_int16* data_length;
    std::string upload_data;

    /*  Event variables */
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    func_status = (u_char*) (data + offset);
    offset += 1;

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        offset += 2; //Skip unknown bytes
        upload_id = (u_int32*) (data + offset);
        offset += 4;

        ev = s7_job_upload;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(val_mgr->Count((short)*func_status));
        vl.emplace_back(val_mgr->Count(ntohl(*upload_id)));
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        data_length = (u_int16*) (data + offset);
        offset += 4; // 2 + 2 unknown bytes
        upload_data = HexToString((data + offset), ntohs(*data_length));
        offset += (short)*data_length;

        ev = s7_ackdata_upload;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
        vl.emplace_back(val_mgr->Count((short)*func_status));
        vl.emplace_back(val_mgr->Count(ntohs(*data_length)));
        vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(upload_data)});
    }
    
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseEndUpload(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_int16* error_code;
    u_int32* upload_id;

    /*  Event variables */
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        func_status = (u_char*) (data + offset);
        offset += 1;
        error_code = (u_int16*) (data + offset);
        offset += 2;
        upload_id = (u_int32*) (data + offset);
        offset += 4;

        ev = s7_job_end_upload;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(val_mgr->Count((short)*func_status));
        vl.emplace_back(val_mgr->Count(ntohs(*error_code)));
        vl.emplace_back(val_mgr->Count(ntohl(*upload_id)));
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        // No data in parameter or data section, just call an event
        ev = s7_ackdata_end_upload;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseRequestDownload(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_char* filename_length;
    std::string filename;
    u_char* length_part_2;
    std::string length_load_memory;
    std::string length_mc7_code;

    /*  Event variables */
    RecordVal* item;
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        func_status = (u_char*) (data + offset);
        offset += 7; // 1 + 6 unknown bytes
        
        filename_length = (u_char*) (data + offset);
        offset += 1;
        filename = HexToASCII((data + offset), (short)*filename_length);
        offset += (short)*filename_length;

        length_part_2 = (u_char*) (data + offset);
        offset += 2; // 1 + 1 unknown byte

        length_load_memory = HexToASCII((data + offset), 6);
        offset += 6;
        length_mc7_code = HexToASCII((data + offset), 6);
        offset += 6;

        ev = s7_job_request_download;

        item = new RecordVal(BifType::Record::S7Comm::S7JobRequestDownload);
        item->Assign(0, val_mgr->Count((short)*func_status));
        item->Assign(1, val_mgr->Count((short)*filename_length));
        item->Assign(2, new StringVal(filename));
        item->Assign(3, new StringVal(length_load_memory));
        item->Assign(4, new StringVal(length_mc7_code));

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {   
        ev = s7_ackdata_request_download;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseDownloadBlock(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_char* filename_length;
    std::string filename;

    /*  Event variables */
    RecordVal* item;
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        func_status = (u_char*) (data + offset);
        offset += 7; // 1 + 6 unknown bytes

        filename_length = (u_char*) (data + offset);
        offset += 1;
        filename = HexToASCII((data + offset), (short)*filename_length);

        ev = s7_job_download_block;
        
        item = new RecordVal(BifType::Record::S7Comm::S7JobDownloadBlock);
        item->Assign(0, val_mgr->Count((short)*func_status));
        item->Assign(1, val_mgr->Count((short)*filename_length));
        item->Assign(2, new StringVal(filename));
        offset += (short)*filename_length;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});

    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        func_status = (u_char*) (data + offset);
        offset += 1;

        ev = s7_ackdata_download_block;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
        vl.emplace_back(val_mgr->Count((short)*func_status));
        vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseAckDataDownloadData(data)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseDownloadEnded(s7_header* header, const u_char* data)
{
    u_char* func_status;
    u_char* filename_length;
    u_int16* error_code;
    std::string filename;

    /*  Event variables */
    RecordVal* item;
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        func_status = (u_char*) (data + offset);
        offset += 1;
        error_code = (u_int16*) (data + offset);
        offset += 6; // 2 + 4 unknown bytes
        filename_length = (u_char*) (data + offset);
        offset += 1;
        filename = HexToASCII((data + offset), (short)*filename_length);

        ev = s7_job_download_ended;
        
        item = new RecordVal(BifType::Record::S7Comm::S7JobDownloadEnded);
        item->Assign(0, val_mgr->Count((short)*func_status));
        item->Assign(1, val_mgr->Count(ntohs(*error_code)));
        item->Assign(2, val_mgr->Count((short)*filename_length));
        item->Assign(3, new StringVal(filename));

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});

    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        ev = s7_ackdata_download_ended;
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParsePLCControl(s7_header* header, const u_char* data)
{
    /* "Regular" PLC Control items*/
    u_int16* param_length;
    u_char* string_length;
    std::string plc_service;

    /* Parameter block items (INSE / DELE)*/
    u_char* count;

    /* Block offset and index of service name */
    int param_block_offset;
    int idx;

    int blocks = 0;
    int fields = 0;

    /*  Event variables */
    RecordVal* item;
    VectorVal* strings_vec;
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        // Skip unknown bytes
        offset += 7;

        param_length = (u_int16*) (data + offset);
        offset += 2;

        // Remember where to start the parameter block
        param_block_offset = offset;

        // Skip parameter block for now
        offset += ntohs(*param_length);

        string_length = (u_char*) (data + offset);
        offset += 1;

        plc_service = HexToASCII((data + offset), (short)*string_length);
        idx = GetPIServiceIndex(plc_service);

        if(!idx)
        {
            Weird("Unknown PLC Control service type");
            return;
        }

       ev = s7_job_plc_control;
       strings_vec = new VectorVal(zeek::id::string_vec);

       /**
        * Decode service parameter
       */
       switch(idx)
       {
           case S7COMM_PI_INSE:
           case S7COMM_PI_DELE:
           {
               count = (u_char*) (data + param_block_offset);
               param_block_offset += 1;
               // Skip unknown byte
               param_block_offset += 1;

               for(int i = 0; i < (short)*count; i++)
               {
                   strings_vec->Assign(strings_vec->Size(), IntrusivePtr{AdoptRef{}, new StringVal(HexToASCII((data + param_block_offset), 8))});
                   param_block_offset += 8;
               }

               blocks = (short)*count;
               fields = 0;
               break;

           }
           case S7COMM_PIP_PROGRAM:
           case S7COMM_PI_MODU:
           case S7COMM_PI_GARB:
           {
               if(!ntohs(*param_length))
               {
                   strings_vec->Assign(strings_vec->Size(), IntrusivePtr{AdoptRef{}, new StringVal("")}); //Just to make sure it is initialized
               }
               else
               {
                   strings_vec->Assign(strings_vec->Size(), IntrusivePtr{AdoptRef{}, new StringVal(HexToASCII((data + param_block_offset), ntohs(*param_length)))});
               }

               // No blocks nor fields
               blocks = 0;
               fields = 0;

               break;
           }
           case S7COMM_PI_N_LOGOUT:
           case S7COMM_PI_N_CANCEL:
           case S7COMM_PI_N_DASAVE:
           case S7COMM_PI_N_DIGIOF:
           case S7COMM_PI_N_DIGION:
           case S7COMM_PI_N_DZERO_:
           case S7COMM_PI_N_ENDEXT:
           case S7COMM_PI_N_F_OPER:
           case S7COMM_PI_N_OST_OF:
           case S7COMM_PI_N_OST_ON:
           case S7COMM_PI_N_SCALE_:
           case S7COMM_PI_N_SETUFR:
           case S7COMM_PI_N_STRTLK:
           case S7COMM_PI_N_STRTUL:
           case S7COMM_PI_N_TMRASS:
           {
               DecodePLCControlParameter(data, param_block_offset, 1, strings_vec);

               blocks = 0;
               fields = 1;
               break;
           }
           case S7COMM_PI_N_LOGIN_:
           case S7COMM_PI_N_F_DELE:
           case S7COMM_PI_N_EXTERN:
           case S7COMM_PI_N_EXTMOD:
           case S7COMM_PI_N_F_DELR:
           case S7COMM_PI_N_F_XFER:
           case S7COMM_PI_N_LOCKE_:
           case S7COMM_PI_N_SELECT:
           case S7COMM_PI_N_SRTEXT:
           case S7COMM_PI_N_F_CLOS:
           case S7COMM_PI_N_SEL_BL:
           case S7COMM_PI_N_IBN_SS:
           case S7COMM_PI_N_FINDBL:
           case S7COMM_PI_N_F_DMDA:
           case S7COMM_PI_N_CREACE:
           case S7COMM_PI_N_CREATO:
           case S7COMM_PI_N_DELETO:
           case S7COMM_PI_N_CONFIG:
           {
               DecodePLCControlParameter(data, param_block_offset, 2, strings_vec);

               blocks = 0;
               fields = 2;
               break;
           }
           case S7COMM_PI_N_CRCEDN:
           case S7COMM_PI_N_DELECE:
           case S7COMM_PI_N_CRTOCE:
           case S7COMM_PI_N_F_PROT:
           case S7COMM_PI_N_F_RENA:
           case S7COMM_PI_N_MMCSEM:
           case S7COMM_PI_N_NEWPWD:
           case S7COMM_PI_N_TMGETT:
           case S7COMM_PI_N_TMPCIT:
           {
               DecodePLCControlParameter(data, param_block_offset, 3, strings_vec);

               blocks = 0;
               fields = 3;
               break;
           }
           case S7COMM_PI_N_CHEKDM:
           case S7COMM_PI_N_CHKDNO:
           case S7COMM_PI_N_F_COPY:
           case S7COMM_PI_N_NCKMOD:
           case S7COMM_PI_N_SETTST:
           case S7COMM_PI_N_TMAWCO:
           case S7COMM_PI_N_TMCRTO:
           case S7COMM_PI_N_TRESMO:
           {
               DecodePLCControlParameter(data, param_block_offset, 4, strings_vec);

               blocks = 0;
               fields = 4;
               break;
           }
           case S7COMM_PI_N_TMCRTC:
           {
               DecodePLCControlParameter(data, param_block_offset, 5, strings_vec);

               blocks = 0;
               fields = 5;
               break;
           }
           case S7COMM_PI_N_F_SEEK:
           case S7COMM_PI_N_ASUP__:
           case S7COMM_PI_N_DELVAR:
           case S7COMM_PI_N_TMFDPL:
           case S7COMM_PI_N_TMMVTL:
           {
               DecodePLCControlParameter(data, param_block_offset, 6, strings_vec);

               blocks = 0;
               fields = 6;
               break;
           }
           case S7COMM_PI_N_TMPOSM:
           {
               DecodePLCControlParameter(data, param_block_offset, 6, strings_vec);

               blocks = 0;
               fields = 8;
               break;
           }
           case S7COMM_PI_N_TSEARC:
           {
               DecodePLCControlParameter(data, param_block_offset, 6, strings_vec);

               blocks = 0;
               fields = 9;
               break;
           }
           case S7COMM_PI_N_TMFPBP:
           {
               DecodePLCControlParameter(data, param_block_offset, 6, strings_vec);

               blocks = 0;
               fields = 13;
               break;
           }
       }

       vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
       vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(plc_service)});
       vl.emplace_back(val_mgr->Count(blocks));
       vl.emplace_back(val_mgr->Count(fields));
       vl.emplace_back(IntrusivePtr{AdoptRef{}, strings_vec});
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        ev = s7_ackdata_plc_control;
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParsePLCStop(s7_header* header, const u_char* data)
{
    u_char* string_length;
    std::string filename;

    /*  Event variables */
    EventHandlerPtr ev;
    Args vl;

    vl.emplace_back(ConnVal());

    if(header->msg_type == S7COMM_ROSCTR_JOB)
    {
        // Skip unknown bytes
        offset += 5;

        string_length = (u_char*) (data + offset);
        offset += 1;
        filename = HexToASCII((data + offset), (short)*string_length);

        ev = s7_job_plc_stop;

        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(filename)});
    }
    else if(header->msg_type == S7COMM_ROSCTR_ACK_DATA)
    {
        ev = s7_ackdata_plc_stop;
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDParameter(s7_header* header, int len, const u_char* data, bool orig)
{
    std::string param_header;
    u_char* param_length;
    u_char* req_resp;
    u_char* type_functiongroup;
    u_char* subfunction_ptr;
    u_char* sequence_number;

    // If parameter length is >= 12
    u_char* data_unit_ref_number = 0;
    bool last_data_unit = true;
    u_int16* error_code;

    // Pointer -> short/integer
    short type;
    short function_group;
    short subfunction;
    int offset_temp;

    offset_temp = offset;

    param_header = HexToString((data + offset), 3);
    offset += 3;
    param_length = (u_char*) (data + offset);
    offset += 1;
    req_resp = (u_char*) (data + offset);
    offset += 1;
    type_functiongroup = (u_char*) (data + offset);
    offset += 1;

    type = (short)((*type_functiongroup & 0xF0) >> 4);
    function_group = (short)(*type_functiongroup & 0x0F);

    subfunction_ptr = (u_char*) (data + offset);
    subfunction = (short) *subfunction_ptr;
    offset += 1;

    sequence_number = (u_char*) (data + offset);
    offset += 1;

    // To determine if data_unit_ref_number, last_data_unit and
    // error_code are necessary
    if(ntohs(header->parameter_length) >= 12)
    {
        data_unit_ref_number = (u_char*) (data + offset);
        offset += 1;

        // Check if this packet is the last data unit
        // If it is != 0, it's not
        if(*(data + offset))
        {
            last_data_unit = false;
        }
        else
        {
            last_data_unit = true;
        }
        offset += 1;

        error_code = (u_int16*) (data + offset);
        offset += 2;
    }
    switch (function_group)
    {
        case S7COMM_UD_FUNCGROUP_PROG:
        {
            ParseUDProgSubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_CYCLIC:
        {
            ParseUDCyclSubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_BLOCK:
        {
            ParseUDBlockSubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_CPU:
        {
            if(ntohs(header->parameter_length) >= 12)
            {
                ParseUDCPUSubfunction(header, data, subfunction, (short)*data_unit_ref_number, last_data_unit, type);
            }
            else
            {
                ParseUDCPUSubfunction(header, data, subfunction, 0, last_data_unit, type);
            }
            break;
        }
        case S7COMM_UD_FUNCGROUP_SEC:
        {
            ParseUDSecuritySubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_PBC:
        {
            ParseUDPBCSubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_TIME:
        {
            ParseUDTimeSubfunction(header, data, subfunction, type);
            break;
        }
        case S7COMM_UD_FUNCGROUP_NCPRG:
        {
            ParseUDNCProgSubfunction(header, data, subfunction, type);
            break;
        }
    }
}

void S7_Comm_Analyzer::ParseUDProgSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
    // Event variables
    Args vl;
    EventHandlerPtr ev;

    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    switch(subfunction)
    {
        case S7COMM_UD_SUBF_PROG_REQDIAGDATA1:
        {
            ev = s7_ud_prog_reqdiagdata1;
            
            if(type != S7COMM_UD_TYPE_PUSH)
            {
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDReqDiagData(subfunction, data)});
            }
            else
            {
                ev = s7_ud_prog_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_PROG_REQDIAGDATA2:
        {
            if(type != S7COMM_UD_TYPE_PUSH)
            {
                ev = s7_ud_prog_reqdiagdata2;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDReqDiagData(subfunction, data)});
            }
            else
            {
                ev = s7_ud_prog_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_PROG_VARTAB1:
        {
            // Lookahead data type
            u_char* data_type = (u_char*) (data + offset + 5);
            
            switch((short)*data_type)
            {
                case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ:
                {
                    ev = s7_ud_prog_vartab1_request;
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDVarTab1Request(subfunction, data)});
                    break;
                }
                case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES:
                {
                    ev = s7_ud_prog_vartab1_response;
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDVarTab1Response(subfunction, data)});
                    break;
                }
                default:
                {
                    ev = s7_ud_prog_unknown;
                    vl.emplace_back(val_mgr->Count(subfunction));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
                    break;
                }
            }
            break;
        }
        default:
        {
            ev = s7_ud_prog_unknown;
            vl.emplace_back(val_mgr->Count(subfunction));
            vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            break;
        }
    }
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDCyclSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
    // Event variables
    Args vl;
    EventHandlerPtr ev;
    bool known = false;

    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    switch(subfunction)
    {
        case S7COMM_UD_SUBF_CYCLIC_MEM:
        case S7COMM_UD_SUBF_CYCLIC_MEM2:
        {
            known = true;
            if(type == S7COMM_UD_TYPE_REQ)
            {
                ParseUDCyclMem(header, packet_type, subfunction, data);
            }
            else if(type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_PUSH)
            {
                ParseUDCyclMemAck(header, packet_type, subfunction, data);
            }
            break;
        }
        case S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE:
        {
            ev = s7_ud_cycl_unsub;
            vl.emplace_back(val_mgr->Count(subfunction));
            vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            break;
        }
    }

    if(!known)
    {
        EnqueueConnEvent(ev, std::move(vl));
    }
}

void S7_Comm_Analyzer::ParseUDBlockSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
     // Event variables
    Args vl;
    EventHandlerPtr ev;

    // Lookahead transportsize
    short return_value = 0;
    short transport_size = 0;
    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    // Lookahead these 2 bytes
    return_value = (short)*(u_char*) (data + offset);
    transport_size = (short)*(u_char*) (data + offset + 1);

    switch(subfunction)
    {
        case S7COMM_UD_SUBF_BLOCK_LIST:
        {
            if(type == S7COMM_UD_TYPE_RES)
            {
                ev = s7_ud_block_list_res;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDBlockListType(subfunction, data)});
            }
            else 
            {
                ev = s7_ud_block_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_BLOCK_LISTTYPE:
        {
            if(type == S7COMM_UD_TYPE_REQ)
            {
                if(transport_size != S7COMM_DATA_TRANSPORT_SIZE_NULL)
                {
                    ev = s7_ud_block_listtype_req;
                    vl.emplace_back(val_mgr->Count((short)*(u_char*)(data + offset)));
                    vl.emplace_back(val_mgr->Count((short)*(u_char*)(data + offset + 1)));
                    vl.emplace_back(val_mgr->Count(ntohs(*(u_int16*)(data + offset + 2))));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(HexToASCII((data + offset + 4), ntohs(*(u_int16*)(data + offset + 2))))});
                }
                else // No ASCII data, just plain hex output
                {
                    ev = s7_ud_block_unknown;
                    vl.emplace_back(val_mgr->Count(subfunction));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
                }
            }
            else if(type == S7COMM_UD_TYPE_RES)
            {
                if(transport_size != S7COMM_DATA_TRANSPORT_SIZE_NULL)
                {
                    ev = s7_ud_block_listtype_res;
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDBlockListType(subfunction, data)});
                }
                else // No ASCII data, just plain hex output
                {
                    ev = s7_ud_block_unknown;
                    vl.emplace_back(val_mgr->Count(subfunction));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
                }
            }
            else
            {
                ev = s7_ud_block_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_BLOCK_BLOCKINFO:
        {
            if(type == S7COMM_UD_TYPE_REQ)
            {
                if(transport_size != S7COMM_DATA_TRANSPORT_SIZE_NULL)
                {
                    ev = s7_ud_block_blockinfo_req;
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDBlockBlockInfoReq(subfunction, data)});
                }
                else
                {
                    ev = s7_ud_block_unknown;
                    vl.emplace_back(val_mgr->Count(subfunction));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
                }
            }
            else if(type == S7COMM_UD_TYPE_RES)
            {
                if(return_value == S7COMM_ITEM_RETVAL_DATA_OK)
                {
                    ev = s7_ud_block_blockinfo_res;
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDBlockBlockInfoRes(subfunction, data)});
                }
                else
                {
                    ev = s7_ud_block_unknown;
                    vl.emplace_back(val_mgr->Count(subfunction));
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
                }
            }
            else
            {
                ev = s7_ud_block_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        } 
    }
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDCPUSubfunction(s7_header* header, const u_char* data, short subfunction, short data_ref_num, bool last_data, short type)
{
    Args vl;
    EventHandlerPtr ev;

    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    switch(subfunction)
    {
        case S7COMM_UD_SUBF_CPU_READSZL:
        {
            offset += 4; // Skip usual 4 byte data header for now...
            ev = s7_ud_cpu_read_szl;
            vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(HexToString(data + offset, 2))});
            offset += 2;
            vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(HexToString(data + offset, 2))});
            offset += 2;
            break;
        }
        default:
        {
            ev = s7_ud_cpu_unknown;
            vl.emplace_back(val_mgr->Count(subfunction));
            vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            break;
        }
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDSecuritySubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
     // Event variables
    Args vl;
    EventHandlerPtr ev;
    RecordVal* data_rec;

    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    // There is nothing much known about this function, so we parse the whole thing in here
    ev = s7_ud_security;
    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDPBCSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    u_char* var_spec;
    u_char* addr_length;
    u_char* syntax_id;
    u_char* pbc_unknown;
    u_int32* pbc_r_id;
    std::string rest_of_data = "";

     // Event variables
    Args vl;
    EventHandlerPtr ev;
    RecordVal* data_rec;

    std::string packet_type = GetPacketType(type);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    ev = s7_ud_pbc;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    var_spec = (u_char*) (data + offset);
    offset += 1;
    addr_length = (u_char*) (data + offset);
    offset += 1;
    syntax_id = (u_char*) (data + offset);
    offset += 1;
    pbc_unknown = (u_char*) (data + offset);
    offset += 1;
    pbc_r_id = (u_int32*) (data + offset);
    offset += 4;
    rest_of_data = HexToASCII((data + offset), (ntohs(*data_length)- 4 - 8));
    
    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDPBC);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, val_mgr->Count(*var_spec));
    data_rec->Assign(4, val_mgr->Count(*addr_length));
    data_rec->Assign(5, val_mgr->Count(*syntax_id));
    data_rec->Assign(6, val_mgr->Count(*pbc_unknown));
    data_rec->Assign(7, val_mgr->Count(ntohl(*pbc_r_id)));
    data_rec->Assign(8, new StringVal(rest_of_data));

    vl.emplace_back(IntrusivePtr{AdoptRef{}, data_rec});

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDTimeSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
    Args vl;
    EventHandlerPtr ev;
    RecordVal* data_rec;

    // Protocol fields
    u_char* return_value;

    std::string packet_type = GetPacketType(type);

    return_value = (u_char*) (data + offset);

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    switch(subfunction)
    {
        case S7COMM_UD_SUBF_TIME_READ:
        {
            if((short)*return_value == S7COMM_ITEM_RETVAL_DATA_OK && type == S7COMM_UD_TYPE_RES)
            {
                ev = s7_ud_time_read;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseS7Time(data)});
            }
            else
            {
                ev = s7_ud_time_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_TIME_READF:
        {
            if((short)*return_value == S7COMM_ITEM_RETVAL_DATA_OK && type == S7COMM_UD_TYPE_RES)
            {
                ev = s7_ud_time_readf;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseS7Time(data)});
            }
            else
            {
                ev = s7_ud_time_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_TIME_SET:
        {
            if((short)*return_value == S7COMM_ITEM_RETVAL_DATA_OK && type == S7COMM_UD_TYPE_REQ)
            {
                ev = s7_ud_time_set1;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseS7Time(data)});
            }
            else
            {
                ev = s7_ud_time_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
        case S7COMM_UD_SUBF_TIME_SET2:
        {
            if((short)*return_value == S7COMM_ITEM_RETVAL_DATA_OK && type == S7COMM_UD_TYPE_REQ)
            {
                ev = s7_ud_time_set2;
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseS7Time(data)});
            }
            else
            {
                ev = s7_ud_time_unknown;
                vl.emplace_back(val_mgr->Count(subfunction));
                vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});
            }
            break;
        }
    }

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Analyzer::ParseUDNCProgSubfunction(s7_header* header, const u_char* data, short subfunction, short type)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;

    Args vl;
    EventHandlerPtr ev;
    RecordVal* data_rec;

    std::string packet_type = GetPacketType(type);

    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
    vl.emplace_back(val_mgr->Count(subfunction));
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, ParseUDUnknownData(data)});

    ev = s7_ud_ncprog;

    EnqueueConnEvent(ev, std::move(vl));
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDUnknownData(const u_char* data)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    std::string data_string;


    RecordVal * data_rec = 0;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    data_string = HexToString((data + offset), ntohs(*data_length));
    offset += ntohs(*data_length);

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDUnknownData);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, new StringVal(data_string));

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDReqDiagData(short subfunction, const u_char* data)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    u_int16* ask_header_size;
    u_int16* ask_size;
    u_int16* answer_size;
    u_char* block_type;
    u_int16* block_number;
    u_int16* start_addr_awl;
    u_int16* step_addr_counter;
    short number_of_lines;
    short item_size;

    // Item fields
    u_int16* address;
    u_char* registers;

    // Event types
    RecordVal* data_rec;
    RecordVal* item;
    VectorVal* item_vec;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDReqDiagData);
    item_vec = new VectorVal(BifType::Vector::S7Comm::S7UDReqDiagItemVec);

    if(ntohs(*data_length) != 0)
    {
        ask_header_size = (u_int16*) (data + offset);
        offset += 2;
        ask_size = (u_int16*) (data + offset);
        offset += 8; // 2 + 6 unknown bytes
        answer_size = (u_int16*) (data + offset);
        offset += 15; // 2 + 13 unknown bytes
        block_type = (u_char*) (data + offset);
        offset += 1;
        block_number = (u_int16*) (data + offset);
        offset += 2;
        start_addr_awl = (u_int16*) (data + offset);
        offset += 2;
        step_addr_counter = (u_int16*) (data + offset);
        offset += 3; // 2 + 1 unknown byte

        // Check subfunction...
        
        if(subfunction == 0x13)
        {
            item_size = 4;
            u_int16* buff = (u_int16*) (data + offset);
            offset += 2;
            number_of_lines = (short)*buff;
            // Skip unknown byte
            offset += 1;
        }
        else 
        {
            item_size = 2;
            number_of_lines = (((short)*ask_size - 2) / 2);
        }

        // Skip register flag
        offset += 1;

        // Parse items..
        for(int i = 0; i < number_of_lines; i++)
        {
            if(subfunction == 0x13)
            {
                address = (u_int16*) (data + offset);
                offset += 2;
            }
            // Skip unknown byte
            offset += 1;
            registers = (u_char*) (data + offset);
            offset += 1;

            item = new RecordVal(BifType::Record::S7Comm::S7UDReqDiagItem);
            if(subfunction == 0x13)
            {
                item->Assign(0, val_mgr->Count(ntohs(*address)));
            }
            else
            {
                item->Assign(0, val_mgr->Int(-1));
            }
            item->Assign(1, val_mgr->Count((short)*registers));
            item_vec->Assign(item_vec->Size(), IntrusivePtr{AdoptRef{}, item});
        }

        data_rec->Assign(0, val_mgr->Count(*return_code));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(ntohs(*ask_header_size)));
        data_rec->Assign(4, val_mgr->Count(ntohs(*ask_size)));
        data_rec->Assign(5, val_mgr->Count(ntohs(*answer_size)));
        data_rec->Assign(6, val_mgr->Count(*block_type));
        data_rec->Assign(7, val_mgr->Count(ntohs(*block_number)));
        data_rec->Assign(8, val_mgr->Count(ntohs(*start_addr_awl)));
        data_rec->Assign(9, val_mgr->Count(ntohs(*step_addr_counter)));
        data_rec->Assign(10, IntrusivePtr{AdoptRef{}, item_vec});
    }
    else
    {
        data_rec->Assign(0, val_mgr->Count(*return_code));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(0));
        data_rec->Assign(4, val_mgr->Count(0));
        data_rec->Assign(5, val_mgr->Count(0));
        data_rec->Assign(6, val_mgr->Count(0));
        data_rec->Assign(7, val_mgr->Count(0));
        data_rec->Assign(8, val_mgr->Count(0));
        data_rec->Assign(9, val_mgr->Count(0));
        data_rec->Assign(10, IntrusivePtr{AdoptRef{}, item_vec});
    }
    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDProgUnknownData(short subfunction, const u_char* data)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* length;
    std::string data_string;

    // Event types
    RecordVal* data_rec;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    length = (u_int16*) (data + offset);
    offset += 2;

    data_string = HexToString((data + offset), ntohs(*length));

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDUnknownData);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*length)));
    data_rec->Assign(3, new StringVal(data_string));

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDVarTab1Request(short subfunction, const u_char* data)
{
    // First 3 data fields
    u_char* return_value;
    u_char* transport_size;
    u_int16* data_length;

    // VarTab data fields
    u_char* data_type;
    u_int16* byte_count;
    u_int16* item_count;

    // Item fields
    u_char* mem_area;
    u_char* rep_fac;
    u_int16* db_number;
    u_int16* start_addr;

    // Event variables
    RecordVal* data_rec;
    RecordVal* item_rec;
    VectorVal* item_vec;

    // Begin parsing
    return_value = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;

    item_vec = new VectorVal(BifType::Vector::S7Comm::S7UDVarTab1ReqItemVec);
    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDVarTab1ReqData);

    if(ntohs(*data_length) != 0)
    {
        // Skip constant 0 byte
        offset += 1;

        data_type = (u_char*) (data + offset);
        offset += 1;
        byte_count = (u_int16*) (data + offset);
        offset += 22; // 2 + 20 unknown bytes
        item_count = (u_int16*) (data + offset);
        offset += 2;

        for(int i = 0; i < ntohs(*item_count); i++)
        {
            mem_area = (u_char*) (data + offset);
            offset += 1;
            rep_fac = (u_char*) (data + offset);
            offset += 1;
            db_number = (u_int16*) (data + offset);
            offset += 2;
            start_addr = (u_int16*) (data + offset);
            offset += 2;

            item_rec = new RecordVal(BifType::Record::S7Comm::S7UDVarTab1ReqItem);
            item_rec->Assign(0, val_mgr->Count(*mem_area));
            item_rec->Assign(1, val_mgr->Count(*rep_fac));
            item_rec->Assign(2, val_mgr->Count(ntohs(*db_number)));
            item_rec->Assign(3, val_mgr->Count(ntohs(*start_addr)));
            item_vec->Assign(item_vec->Size(), IntrusivePtr{AdoptRef{}, item_rec});
        }

        data_rec->Assign(0, val_mgr->Count(*return_value));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(*data_type));
        data_rec->Assign(4, val_mgr->Count(ntohs(*byte_count)));
        data_rec->Assign(5, val_mgr->Count(ntohs(*item_count)));
        data_rec->Assign(6, IntrusivePtr{AdoptRef{}, item_vec});
    }
    else
    {
        data_rec->Assign(0, val_mgr->Count(*return_value));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(0));
        data_rec->Assign(4, val_mgr->Count(0));
        data_rec->Assign(5, val_mgr->Count(0));
        data_rec->Assign(6, IntrusivePtr{AdoptRef{}, item_vec});
    }

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDVarTab1Response(short subfunction, const u_char* data)
{
    // First 3 data fields
    u_char* return_value;
    u_char* transport_size;
    u_int16* data_length;

    // VarTab data fields
    u_char* data_type;
    u_int16* byte_count;
    u_int16* item_count;

    // Item fields
    u_char* ret_value;
    u_char* t_size;
    u_int16* ret_length;
    std::string ret_data;

    // Short representation of item fields
    short ret_val_s = 0;
    short t_size_s = 0;
    short len = 0, len2 = 0;

    // Event variables
    RecordVal* data_rec;
    RecordVal* item_rec;
    VectorVal* item_vec;

    // Begin parsing
    return_value = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;

    item_vec = new VectorVal(BifType::Vector::S7Comm::S7UDVarTab1ResItemVec);
    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDVarTab1ResData);

    if(ntohs(*data_length) != 0)
    {
        // Skip constant 0 byte
        offset += 1;

        data_type = (u_char*) (data + offset);
        offset += 1;
        byte_count = (u_int16*) (data + offset);
        offset += 6; // 2 + 4 unknown bytes;
        item_count = (u_int16*) (data + offset);
        offset += 2;

        for(int i = 0; i < ntohs(*item_count); i++)
        {
            ret_value = (u_char*) (data + offset);
            offset += 1;
            
            ret_val_s = (short)*ret_value;

            if(ret_val_s == S7COMM_ITEM_RETVAL_RESERVED || ret_val_s == S7COMM_ITEM_RETVAL_DATA_OK || ret_val_s == S7COMM_ITEM_RETVAL_DATA_ERR)
            {
                t_size = (u_char*) (data + offset);
                offset += 1;
                ret_length = (u_int16*) (data + offset);
                offset += 2;

                t_size_s = (short)*t_size;
                len = ntohs(*ret_length);

                if(t_size_s == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || t_size_s == S7COMM_DATA_TRANSPORT_SIZE_BINT)
                {
                    len /= 8;
                }

                if(len % 2)
                {
                    len2 = len + 1;
                }
                else
                {
                    len2 = len;
                }
            }

            ret_data = HexToString((data + offset), len);
            offset += len;

            if(len != len2)
            {
                // Requires fillbyte
                offset += 1;
            }

            item_rec = new RecordVal(BifType::Record::S7Comm::S7UDVarTab1ResItem);
            item_rec->Assign(0, val_mgr->Count(ret_val_s));
            item_rec->Assign(1, val_mgr->Count(t_size_s));
            item_rec->Assign(2, val_mgr->Count(len));
            item_rec->Assign(3, new StringVal(ret_data));
            item_vec->Assign(item_vec->Size(), IntrusivePtr{AdoptRef{}, item_rec});
        }

        data_rec->Assign(0, val_mgr->Count(*return_value));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(*data_type));
        data_rec->Assign(4, val_mgr->Count(ntohs(*byte_count)));
        data_rec->Assign(5, val_mgr->Count(ntohs(*item_count)));
        data_rec->Assign(6, IntrusivePtr{AdoptRef{}, item_vec});
    }
    else
    {
        data_rec->Assign(0, val_mgr->Count(*return_value));
        data_rec->Assign(1, val_mgr->Count(*transport_size));
        data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
        data_rec->Assign(3, val_mgr->Count(0));
        data_rec->Assign(4, val_mgr->Count(0));
        data_rec->Assign(5, val_mgr->Count(0));
        data_rec->Assign(6, IntrusivePtr{AdoptRef{}, item_vec});
    }
    return data_rec;
}

void S7_Comm_Analyzer::ParseUDCyclMem(s7_header* header, std::string packet_type, short subfunction, const u_char* data)
{
    // Data fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    u_int16* item_count;
    u_char* interval_timebase;
    u_char* interval_time;

    // Lookahead first item type
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;

    // Bro types
    RecordVal* item = 0;
    Args vl;
    EventHandlerPtr ev = 0;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    item_count = (u_int16*) (data + offset);
    offset += 2;
    interval_timebase = (u_char*) (data + offset);
    offset += 1;
    interval_time = (u_char*) (data + offset);
    offset += 1;

    // Lookahead to determine item type...
    for(int i = 0; i < ntohs(*item_count); i++)
    {
        var_spec_typ = (u_char*) (data + offset);
        addr_length = (u_char*) (data + offset + 1);
        syntax_id = (u_char*) (data + offset + 2);

        if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_S7ANY)
        {
            ev = s7_ud_cycl_mem_any;
            item = ParseAnyItem(data);
        }
        else if(*var_spec_typ == 0x12 && *addr_length >= 7 && *syntax_id == S7COMM_SYNTAXID_DBREAD)
        {
            ev = s7_ud_cycl_mem_any;
            item = ParseAnyItem(data);
        }
        else if(*var_spec_typ == 0x12 && *addr_length >= 14 && *syntax_id == S7COMM_SYNTAXID_1200SYM)
        {
            ev = s7_ud_cycl_mem_any;
            item = ParseAnyItem(data);
        }
        else if(*var_spec_typ == 0x12 && *addr_length == 8 && *syntax_id == S7COMM_SYNTAXID_NCK)
        {
            ev = s7_ud_cycl_mem_any;
            item = ParseAnyItem(data);
        }
        else if(*var_spec_typ == 0x12 && *addr_length == 10 && *syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
        {
            ev = s7_ud_cycl_mem_any;
            item = ParseAnyItem(data);
        }
        else
        {
            Weird("S7_UD_Cycl: Unsupported variable specification...");
            continue;
        }
        vl.emplace_back(ConnVal());
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeader(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});
        vl.emplace_back(val_mgr->Count(*return_code));
        vl.emplace_back(val_mgr->Count(*transport_size));
        vl.emplace_back(val_mgr->Count(ntohs(*item_count)));
        vl.emplace_back(val_mgr->Count(i+1));
        vl.emplace_back(val_mgr->Count(*interval_timebase));
        vl.emplace_back(val_mgr->Count(*interval_time));
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});

        EnqueueConnEvent(ev, std::move(vl));
    }
}

void S7_Comm_Analyzer::ParseUDCyclMemAck(s7_header* header, std::string packet_type, short subfunction, const u_char* data)
{
    // Data fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    u_int16* item_count;

    // Bro types
    RecordVal* item;
    Args vl;
    EventHandlerPtr ev = 0;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    item_count = (u_int16*) (data + offset);
    offset += 2;

    for(int i = 0; i < ntohs(*item_count); i++)
    {
        item = ParseReadWriteData(data, (short)*item_count-i);
        
        if(item->GetType() == BifType::Record::S7Comm::S7NCKTypeItem)
        {
            ev = s7_ud_cycl_mem_ack_nck;  
        }
        else
        {
            ev = s7_ud_cycl_mem_ack;
        }

        vl.emplace_back(ConnVal());
        vl.emplace_back(IntrusivePtr{AdoptRef{}, CreateHeaderWithError(header)});
        vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});
        vl.emplace_back(val_mgr->Count(*return_code));
        vl.emplace_back(val_mgr->Count(*transport_size));
        vl.emplace_back(val_mgr->Count(ntohs(*item_count)));
        vl.emplace_back(val_mgr->Count(i+1));
        vl.emplace_back(IntrusivePtr{AdoptRef{}, item});
        EnqueueConnEvent(ev, std::move(vl));
    }
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDBlockListType(short subfunction, const u_char* data)
{
    // Data fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;

    // S7COMM_UD_SUBF_BLOCK_LIST fields
    u_int16* block_type;
    u_int16* block_count;

    //S7COMM_UD_SUBF_BLOCK_LISTTYPE fields
    u_int16* block_number;
    u_char* block_flags;
    u_char* block_language;

    short item_count = 0;

    // Bro types
    RecordVal* data_rec = 0;
    RecordVal* item = 0;
    VectorVal* item_vec = 0;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;

    item_count = ntohs(*data_length) / 4;

    if(subfunction == S7COMM_UD_SUBF_BLOCK_LIST)
    {
        data_rec = new RecordVal(BifType::Record::S7Comm::S7UDBlockList);
        item_vec = new VectorVal(BifType::Vector::S7Comm::S7UDBlockListVec);
    }
    else if(subfunction == S7COMM_UD_SUBF_BLOCK_LISTTYPE)
    {
        data_rec = new RecordVal(BifType::Record::S7Comm::S7UDBlockListType);
        item_vec = new VectorVal(BifType::Vector::S7Comm::S7UDBlockListTypeVec);
    }

    for(int i = 0; i < item_count; i++)
    {
        if(subfunction == S7COMM_UD_SUBF_BLOCK_LIST)
        {
            block_type = (u_int16*) (data + offset);
            offset += 2;
            block_count = (u_int16*) (data + offset);
            offset += 2;

            item = new RecordVal(BifType::Record::S7Comm::S7UDBlockListItem);
            item->Assign(0, val_mgr->Count(ntohs(*block_type)));
            item->Assign(1, val_mgr->Count(ntohs(*block_count)));
            item_vec->Assign(item_vec->Size(), IntrusivePtr{AdoptRef{}, item});
        }
        else if(subfunction == S7COMM_UD_SUBF_BLOCK_LISTTYPE)
        {
            block_number = (u_int16*) (data + offset);
            offset += 2;
            block_flags = (u_char*) (data + offset);
            offset += 1;
            block_language = (u_char*) (data + offset);
            offset += 1;

            item = new RecordVal(BifType::Record::S7Comm::S7UDBlockListTypeItem);
            item->Assign(0, val_mgr->Count(ntohs(*block_number)));
            item->Assign(1, val_mgr->Count(*block_flags));
            item->Assign(2, val_mgr->Count(*block_language));
            item_vec->Assign(item_vec->Size(), IntrusivePtr{AdoptRef{}, item});
        }
    }

    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, IntrusivePtr{AdoptRef{}, item_vec});

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDBlockBlockInfoReq(short subfunction, const u_char* data)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    std::string block_type;
    std::string block_number;
    std::string filesystem;

    // Bro types
    RecordVal* data_rec = 0;

    // Begin parsing...
    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    block_type = HexToASCII((data + offset), 2);
    offset += 2;
    block_number = HexToASCII((data + offset), 5);
    offset += 5;
    filesystem = HexToASCII((data + offset), 1);
    offset += 1;

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDBlockInfoReq);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, new StringVal(block_type));
    data_rec->Assign(4, new StringVal(block_number));
    data_rec->Assign(5, new StringVal(filesystem));

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseUDBlockBlockInfoRes(short subfunction, const u_char* data)
{
    // Protocol fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    u_int16* block_type;
    u_int16* info_length;
    u_char* block_flags;
    u_char* block_language;
    u_char* subblk_type;
    u_int16* block_number;
    u_int32* length_load_memory;
    u_int32* block_security;
    std::string code_timestamp;
    std::string interface_timestamp;
    u_int16* ssb_length;
    u_int16* add_length;
    u_int16* localdata_length;
    u_int16* mc7_code_length;
    std::string author; // 8 Byte
    std::string family; // 8 Byte
    std::string name; //8 Byte
    u_char* version;
    std::string block_checksum; // in hex
    std::string reserved1; // 4 Byte
    std::string reserved2; // 4 Byte

    // Bro types
    RecordVal* data_rec = 0;

    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    block_type = (u_int16*) (data + offset);
    offset += 2;
    info_length = (u_int16*) (data + offset);
    offset += 7; // 2 + 5 unknown/not used bytes -> unknown (2), constant (2) and more unknown (1) bytes
    block_flags = (u_char*) (data + offset);
    offset += 1;
    block_language = (u_char*) (data + offset);
    offset += 1;
    subblk_type = (u_char*) (data + offset);
    offset += 1;
    block_number = (u_int16*) (data + offset);
    offset += 2;
    length_load_memory = (u_int32*) (data + offset);
    offset += 4;
    block_security = (u_int32*) (data + offset);
    offset += 4;
    code_timestamp = TimestampToString(data);
    offset += 6;
    interface_timestamp = TimestampToString(data);
    offset += 6;
    ssb_length = (u_int16*) (data + offset);
    offset += 2;
    add_length = (u_int16*) (data + offset);
    offset += 2;
    localdata_length = (u_int16*) (data + offset);
    offset += 2;
    mc7_code_length = (u_int16*) (data + offset);
    offset += 2;
    author = HexToASCII((data + offset), 8);
    offset += 8;
    family = HexToASCII((data + offset), 8);
    offset += 8;
    name = HexToASCII((data + offset), 8);
    offset += 8;
    version = (u_char*) (data + offset);
    offset += 2; // 1 + 1 unknown bytes
    block_checksum = HexToString((data + offset), 2);
    offset += 2;
    reserved1 = HexToString((data + offset), 4);
    offset += 4;
    reserved2 = HexToString((data + offset), 4);
    offset += 4;

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDBlockInfoRes);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, val_mgr->Count(ntohs(*block_type)));
    data_rec->Assign(4, val_mgr->Count(ntohs(*info_length)));
    data_rec->Assign(5, val_mgr->Count(*block_flags));
    data_rec->Assign(6, val_mgr->Count(*block_language));
    data_rec->Assign(7, val_mgr->Count(*subblk_type));
    data_rec->Assign(8, val_mgr->Count(ntohs(*block_number)));
    data_rec->Assign(9, val_mgr->Count(ntohl(*length_load_memory)));
    data_rec->Assign(10, val_mgr->Count(ntohl(*block_security)));
    data_rec->Assign(11, new StringVal(code_timestamp));
    data_rec->Assign(12, new StringVal(interface_timestamp));
    data_rec->Assign(13, val_mgr->Count(ntohs(*ssb_length)));
    data_rec->Assign(14, val_mgr->Count(ntohs(*add_length)));
    data_rec->Assign(15, val_mgr->Count(ntohs(*localdata_length)));
    data_rec->Assign(16, val_mgr->Count(ntohs(*mc7_code_length)));
    data_rec->Assign(17, new StringVal(author));
    data_rec->Assign(18, new StringVal(family));
    data_rec->Assign(19, new StringVal(name));
    data_rec->Assign(20, val_mgr->Count(*version));
    data_rec->Assign(21, new StringVal(block_checksum));
    data_rec->Assign(22, new StringVal(reserved1));
    data_rec->Assign(23, new StringVal(reserved2));

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseAnyItem(const u_char* data)
{
     // Data fields
    u_char* return_code;
    u_char* transport_size;
    u_int16* data_length;
    std::string timestamp = "";

    RecordVal* data_rec = 0;

    return_code = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    data_length = (u_int16*) (data + offset);
    offset += 2;
    timestamp = S7TimeStampToString((data + offset), 10);
    offset += 10;

    data_rec = new RecordVal(BifType::Record::S7Comm::S7UDTime);
    data_rec->Assign(0, val_mgr->Count(*return_code));
    data_rec->Assign(1, val_mgr->Count(*transport_size));
    data_rec->Assign(2, val_mgr->Count(ntohs(*data_length)));
    data_rec->Assign(3, new StringVal(timestamp));

    return data_rec;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseS7Time(const u_char* data)
{
    /* Any Type fields */
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;
    u_char* transport_size;
    u_int16* length;
    u_int16* db_number;
    u_char* area;
    std::string address;

    /* Event variables */
    RecordVal* item = 0;
    EventHandlerPtr ev;

    // TODO: Change this to a struct
    var_spec_typ = (u_char*) (data + offset);
    offset += 1;
    addr_length = (u_char*) (data + offset);
    offset += 1;
    syntax_id = (u_char*) (data + offset);
    offset += 1;
    transport_size = (u_char*) (data + offset);
    offset += 1;
    length = (u_int16*) (data + offset);
    offset += 2;
    db_number = (u_int16*) (data + offset);
    offset += 2;
    area = (u_char*) (data + offset);
    offset += 1;

    // Calculate offsets
    // Little bit tricky: The address contains 3 bytes, but I only have int32 or int64
    // Solution: Take the int64, put in 2 bytes, shift does bytes 8 bit to the left and
    // "or" them with the last byte

    // First get the value out of the stream
    u_int16* byte_offset = (u_int16*) (data + offset);
    u_char* bit_offset = (u_char*) (data + offset + 2);
    int64 byte_bit_offset = 0; 
    byte_bit_offset |= ntohs(*byte_offset);
    byte_bit_offset <<= 8;
    byte_bit_offset |= *bit_offset;

    // The whole address as string
    address = HexToString((data + offset), 3);
    offset += 3;

    item = new RecordVal(BifType::Record::S7Comm::S7AnyTypeItem);
    item->Assign(0, val_mgr->Count(*transport_size));
    item->Assign(1, val_mgr->Count(ntohs(*length)));
    item->Assign(2, val_mgr->Count(ntohs(*db_number)));
    item->Assign(3, val_mgr->Count(*area));
    item->Assign(4, val_mgr->Count((byte_bit_offset >> 3)));
    item->Assign(5, val_mgr->Count((byte_bit_offset & 0x7)));
    item->Assign(6, new StringVal(address));

    return item;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseDbItem(const u_char* data)
{
    /* DB Item fields */
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;
    u_char* subitems;

    /* Subitem fields */
    u_char* bytes_to_read;
    u_int16* db_number;
    u_int16* start_address;

    /* Event variables */
    RecordVal* item = 0;
    VectorVal* v_subitems = 0;
    RecordVal* r_subitem = 0;
    EventHandlerPtr ev;

    var_spec_typ = (u_char*) (data + offset);
    offset += 1;
    addr_length = (u_char*) (data + offset);
    offset += 1;
    syntax_id = (u_char*) (data + offset);
    offset += 1;
    subitems = (u_char*) (data + offset);
    offset += 1;

    item = new RecordVal(BifType::Record::S7Comm::S7DBTypeItem);
    v_subitems = new VectorVal(BifType::Vector::S7Comm::S7DBTypeSubitemVector);
    item->Assign(0, val_mgr->Count((short)*subitems));

    for(int j = 0; j< (short)*subitems; j++)
    {
        bytes_to_read = (u_char*) (data+offset);
        offset += 1;
        db_number = (u_int16*) (data+offset);
        offset += 2;
        start_address = (u_int16*) (data+offset);
        offset += 2;

        r_subitem = new RecordVal(BifType::Record::S7Comm::S7DBTypeSubitem);
        r_subitem->Assign(0, val_mgr->Count((short)*bytes_to_read));
        r_subitem->Assign(1, val_mgr->Count(ntohs(*db_number)));
        r_subitem->Assign(2, val_mgr->Count(ntohs(*start_address)));

        v_subitems->Assign(v_subitems->Size(), IntrusivePtr{AdoptRef{}, r_subitem});
    }

    item->Assign(1, IntrusivePtr{AdoptRef{}, v_subitems});

    return item;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseSymItem(const u_char *data)
{
    /* SYM Item fields */ 
    u_char* var_spec_typ;
    u_char* addr_length;
    u_char* syntax_id;
    u_char* reserved;
    u_int16* area1;
    u_int16* area2;
    u_int32* crc;
    u_int32* substructure;

    /* Event variables */
    RecordVal* item = 0;
    VectorVal* v_substructs = 0;
    RecordVal* r_subtruct = 0;
    EventHandlerPtr ev;

    var_spec_typ = (u_char*) (data + offset);
    offset += 1;
    addr_length = (u_char*) (data + offset);
    offset += 1;
    syntax_id = (u_char*) (data + offset);
    offset += 1;
    reserved = (u_char*) (data + offset);
    offset += 1;
    area1 = (u_int16*) (data + offset);
    offset += 2;
    area2 = (u_int16*) (data + offset);
    offset += 2;
    crc = (u_int32*) (data + offset);
    offset += 4;

    item = new RecordVal(BifType::Record::S7Comm::S71200SymTypeItem);
    v_substructs = new VectorVal(BifType::Vector::S7Comm::S71200SymSubstructurVector);

    item->Assign(0, val_mgr->Count((short)*reserved));
    item->Assign(1, val_mgr->Count((short)*area1));
    item->Assign(2, val_mgr->Count((short)*area2));
    item->Assign(3, val_mgr->Count((short)*crc));

    for(int i = 0; i < ((short)*addr_length - 10) / 4; i++)
    {
        substructure = (u_int32*) (data + offset);
        r_subtruct = new RecordVal(BifType::Record::S7Comm::S71200SymSubstructurItem);
        r_subtruct->Assign(0, val_mgr->Count(((4 >> *substructure) & 0xF)));
        r_subtruct->Assign(1, val_mgr->Count(ntohl(*substructure) & 0x0FFFFFF));

        v_substructs->Assign(v_substructs->Size(), IntrusivePtr{AdoptRef{}, r_subtruct});
        offset += 4;
    }

    item->Assign(4, IntrusivePtr{AdoptRef{}, v_substructs});

    return item;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseNckItem(const u_char *data)
{
    /* NCK Item fields */ 
    u_char* nck_area;
    u_char* nck_module;
    u_char* nck_linecount;
    u_int16* nck_column;
    u_int16* nck_line;

    /* Event variables */
    RecordVal* item = 0;
    EventHandlerPtr ev = 0;

    nck_area = (u_char*)(data + offset);
    offset += 1;
    nck_column = (u_int16*)(data + offset);
    offset += 2;
    nck_line = (u_int16*)(data + offset);
    offset += 2;
    nck_module = (u_char*)(data + offset);
    offset += 1;
    nck_linecount = (u_char*)(data + offset);
    offset += 1;

    item = new RecordVal(BifType::Record::S7Comm::S7NCKTypeItem);

    item->Assign(0, val_mgr->Count((short)*nck_area));
    item->Assign(1, val_mgr->Count(ntohs(*nck_column)));
    item->Assign(2, val_mgr->Count(ntohs(*nck_line)));
    item->Assign(3, val_mgr->Count((short)*nck_module));
    item->Assign(4, val_mgr->Count((short)*nck_linecount));

    return item;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseDriveAnyItem(const u_char *data)
{
    /* NCK Item fields */
    /* Only 2 field are known, the rest is unknown... */
    u_int16* nr;
    u_int16* idx;

    /* Event variables */
    RecordVal* item = 0;
    EventHandlerPtr ev = 0;

    // Skip unknown fields
    offset += 5;

    nr = (u_int16*)(data + offset);
    offset += 2;
    idx = (u_int16*)(data + offset);
    offset += 2;

    item = new RecordVal(BifType::Record::S7Comm::S7DriveAnyTypeItem);

    item->Assign(0, val_mgr->Count(ntohs(*nr)));
    item->Assign(1, val_mgr->Count(ntohs(*idx)));

    return item;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseReadWriteData(const u_char* data, short item_count)
{
    /* Read Data items */
    u_char* return_code;
    u_char* transport_size;
    u_int16* length;
    std::string data_str;
    
    /**
     * Used to calculate the length of the data (if the transportsize is bit, byte or int)
     * and to determine if a filling bit is necessary
    */
    u_int16 len = 0, len2 = 0;

    /* Event variables */
    RecordVal* item = 0, *data_field = 0;
    EventHandlerPtr ev = 0;

    /* Lookahead transportsize */
    transport_size = (u_char*) (data + offset + 1);

    /* Only valid for Sinumerik NCK: Pre-check transport size
     * if transport size is 0x11 or 0x12, then an array with
     * requestes NCK areas will follow...
     * See Wireshark dissector line 2753
     */
    if(*transport_size == S7COMM_DATA_TRANSPORT_SIZE_NCKADDR1 || *transport_size == S7COMM_DATA_TRANSPORT_SIZE_NCKADDR2 )
    {
        return_code = (u_char*) (data + offset);
        offset += 1;
        transport_size = (u_char*) (data + offset);
        offset += 1;
        
        item = ParseNckItem(data);

        return item;
    }
    else
    {
        return_code = (u_char*) (data + offset);

        if(*return_code == S7COMM_ITEM_RETVAL_RESERVED || *return_code == S7COMM_ITEM_RETVAL_DATA_OK  || *return_code == S7COMM_ITEM_RETVAL_DATA_ERR)
        {
            transport_size = (u_char*) (data + offset + 1);
            length = (u_int16*) (data + offset + 2);

            len = ntohs(*length);

            /* given length is in number of bits (see Wireshark dissector line 2774)
            * so we have to divide through 8 to get the length
            */
            if(*transport_size == S7COMM_DATA_TRANSPORT_SIZE_BBIT || *transport_size == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || *transport_size == S7COMM_DATA_TRANSPORT_SIZE_BINT)
            {   
                /* 
                * len is not a multiple of 8, then round up to next number (see Wireshark dissector line 2775)
                */
                if(len % 8) 
                {
                    len /= 8;
                    len += 1;
                }
                else
                {
                    len /= 8;
                }
            }
            /* if len is not a multiple of 2 and that was not the last item, add a filling byte */
            if((len % 2) && ( (item_count-1) > 0))
            {
                len2 = len + 1;
            }
            else
            {
                len2 = len;
            }
        }

        offset += 4;

        data_str = HexToString((data + offset), len);
        offset += len;

        // Adding filling byte
        if(len != len2)
        {
            offset += 1;
        }

        item = new RecordVal(BifType::Record::S7Comm::S7ReadWriteData);  
        item->Assign(0, val_mgr->Count((short)*return_code));
        item->Assign(1, val_mgr->Count((short)*transport_size));
        item->Assign(2, val_mgr->Count(len));
        item->Assign(3, std::move(new StringVal(data_str)));

        return item;
    }
}

short S7_Comm_Analyzer::ParseAckDataWriteData(const u_char* data)
{
    // It's just a simple return code...

    u_char* return_code;

    return_code = (u_char*) (data+offset);
    offset += 1;

    return (short)*return_code;
}

zeek::RecordVal* S7_Comm_Analyzer::CreateHeader(s7_header* header)
{
    RecordVal* h = new RecordVal(BifType::Record::S7Comm::S7Header);

    h->Assign(0, val_mgr->Count((short)header->protocol_id));
    h->Assign(1, val_mgr->Count((short)header->msg_type));
    h->Assign(2, val_mgr->Count(ntohs(header->pdu_ref)));
    h->Assign(3, val_mgr->Count(ntohs(header->parameter_length)));
    h->Assign(4, val_mgr->Count(ntohs(header->data_length)));
    h->Assign(5, val_mgr->Count((short)header->error_class));
    h->Assign(6, val_mgr->Count((short)header->error_code));

    return h;
}

zeek::RecordVal* S7_Comm_Analyzer::CreateHeaderWithError(s7_header* header)
{
    RecordVal* h = new RecordVal(BifType::Record::S7Comm::S7Header);

    h->Assign(0, val_mgr->Count((short)header->protocol_id));
    h->Assign(1, val_mgr->Count((short)header->msg_type));
    h->Assign(2, val_mgr->Count(ntohs(header->pdu_ref)));
    h->Assign(3, val_mgr->Count(ntohs(header->parameter_length)));
    h->Assign(4, val_mgr->Count(ntohs(header->data_length)));
    h->Assign(5, val_mgr->Count((short)header->error_class));
    h->Assign(6, val_mgr->Count((short)header->error_code));

    return h;
}

zeek::RecordVal* S7_Comm_Analyzer::ParseAckDataDownloadData(const u_char* data)
{
    u_int16* data_length;
    std::string download_data;

    RecordVal* item;

    data_length = (u_int16*) (data + offset);
    offset += 4; // 2 + 2 unknown bytes

    download_data = HexToString((data + offset), ntohs(*data_length));

    item = new RecordVal(BifType::Record::S7Comm::S7AckDataDownloadBlock);
    item->Assign(0, val_mgr->Count(ntohs(*data_length)));
    item->Assign(1, new StringVal(download_data));

    return item;
}

std::string S7_Comm_Analyzer::HexToString(const unsigned char* data, int length)
{
    std::string hex = "";

    for(int i = 0; i < length; i++)
    {
        char temp[4];
        std::string buffer;
        sprintf(temp, "%02x", data[i]);
        
        if((data[i] & 0xFF) < 16)
        {
            //buffer += "0";
            buffer += temp;
        }
        else
        {
            buffer +=temp;
        }
        hex += buffer;
    }
    return hex;
}

std::string S7_Comm_Analyzer::HexToASCII(const unsigned char* data, int length)
{
    std::string ascii = "";

    for(int i = 0; i < length; i++)
    {
        if(!(data[i] < 0x20) && !(data[i] > 0x7E))
        {
            char temp[4];
            std::string buffer;
            sprintf(temp, "%x", data[i]);
            buffer += temp;
            char chr = (char) (int)strtol(buffer.c_str(), NULL, 16);
            ascii.push_back(chr);
        }
    }
    return ascii;
}

std::string S7_Comm_Analyzer::GetPacketType(short type)
{
    std::string packet_type = "";

    switch(type)
    {
        case S7COMM_UD_TYPE_PUSH:
        {
            packet_type = "Push";
            break;
        }
        case S7COMM_UD_TYPE_REQ:
        {
            packet_type = "Request";
            break;
        }
        case S7COMM_UD_TYPE_RES:
        {
            packet_type = "Response";
            break;
        }
    }

    return packet_type;
}

std::string S7_Comm_Analyzer::TimestampToString(const u_char* data)
{
    u_int32* day_milliseconds;
    u_int16* days;
    struct tm *mt;
    time_t t;
    char timestamp[30];
    static const char mon_names[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    day_milliseconds = (u_int32*) (data + offset);
    days = (u_int16*) (data + offset + 4);

    t = 441763200L;
    t += (ntohs(*days) * 24 * 60 * 60);
    t += (ntohl(*day_milliseconds) / 1000);
    mt = gmtime(&t);

    if(mt != NULL)
    {
        snprintf(timestamp, 30, "%2d %s %d, %02d:%02d:%02d.%03d", mt->tm_mday, 
        mon_names[mt->tm_mon],mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec, *day_milliseconds % 1000);
    }

    return std::string(timestamp);
}

std::string S7_Comm_Analyzer::S7TimeStampToString(const u_char* data, short bytes)
{
    std::string day_names[7] = {"Sunday", "Monday", "Thusday", "Wednesday", "Thursday", "Friday", "Saturday"};
    std::string timestamp[10];
    std::string milliseconds;
    std::string weekday;

    if(bytes == 10)
    {
        timestamp[0] = HexToString((data), 1);
        timestamp[1] = HexToString((data + 1), 1);
    }
    else
    {
        // ignore the first byte
        timestamp[0] = "00";
        timestamp[1] = "19";
    }

    for(int i = 2; i < 10; i++)
    {
        timestamp[i] = HexToString((data + i), 1);
    }

    // I didn't want to write a new function to calculate the 
    // string values based on char*. Basically, Milliseconds and Weekday,
    // both are cover by the same 2 bytes, but Milliseconds uses 12 Bit while
    // Weekday only uses 4 Bit. 
    // Here I'm concatenating the bytes to create 
    // Milliseconds, but will discard the last nibble,
    milliseconds = timestamp[8] + timestamp[9];
    milliseconds.pop_back();
    // here I'm just looking at the last nibble to determine the Weekday...
    weekday = timestamp[9][1];
    timestamp[8] = milliseconds;
    timestamp[9] = weekday;

    /* year special: ignore the first byte, since some cpus give 1914 for 2014
     * if second byte is below 89, it's 2000..2089, if over 90 it's 1990..1999
     */
    // Wireshark Dissector, line 2327   
    if(std::stoi(timestamp[2], 0, 16) < 89)
    {
        timestamp[1] = "20";
    }
    

    return timestamp[4] 
            + "." + timestamp[3] 
            + "." + timestamp[1] 
            + timestamp[2] + " - " 
            + timestamp[5] + ":"
            + timestamp[6] + ":"
            + timestamp[7] + "."
            + timestamp[8] + " "
            + day_names[std::stoi(timestamp[9], 0, 16) - 1];
}


int S7_Comm_Analyzer::GetPIServiceIndex(std::string plc_service_name)
{
    unsigned int idx = std::find(pi_service_names.begin(), pi_service_names.end(), plc_service_name) - pi_service_names.begin();

    if(idx >= pi_service_names.size())
    {
        idx = 0;
    }

    return idx;
}

void S7_Comm_Analyzer::DecodePLCControlParameter(const u_char* data, int param_offset, int fields, VectorVal* &strings_vec)
{
    u_char* length;

    for(int i = 0; i < fields; i++)
    {
        length = (u_char*) (data + param_offset);
        param_offset += 1;
        strings_vec->Assign(strings_vec->Size(), IntrusivePtr{AdoptRef{}, new StringVal(HexToASCII((data + param_offset),(short)*length))});
    }
}

float S7_Comm_Analyzer::RealToFloat(std::string data)
{
    real_to_float_union u;
    std::stringstream ss(data);
    ss >> std::hex >> u.ul;
    float f = u.f;
    return f;
}