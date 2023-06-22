/**
 * ISO over TCP / S7CommPlus protocol analyzer.
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
#include "S7CommPlus.h"
#include "S7CommPlus_Constants.h"
#include "Event.h"
#include "events.bif.h"
#include "types.bif.h"

using namespace zeek::analyzer::s7_comm_plus;

S7_Comm_Plus_Analyzer::S7_Comm_Plus_Analyzer(Connection* conn): tcp::TCP_ApplicationAnalyzer("S7_Comm_Plus", conn)
{

}

S7_Comm_Plus_Analyzer::~S7_Comm_Plus_Analyzer()
{
    
}

void S7_Comm_Plus_Analyzer::Init()
{
    tcp::TCP_ApplicationAnalyzer::Init();
}

void S7_Comm_Plus_Analyzer::Done()
{
    tcp::TCP_ApplicationAnalyzer::Done();
}

void S7_Comm_Plus_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    // The S7CommPlus packet is divided in 3 parts: header, data, trailer.
    // Header and trailer have always the same structure, data depends on the
    // op- and functioncode.
    
    offset = 0;
    data_offset = 0;
    bool fragmented = false;

    s7plus_header* header = ParseHeader(data);
    s7plus_trailer* trailer = ParseTrailer(data);

    if(header->data_length > 900)
    {
        // Probably fragmented, don't know how to handle yet...
        return;
    }

    ParseData(data, header, trailer);
}

s7plus_header* S7_Comm_Plus_Analyzer::ParseHeader(const u_char* data)
{
    s7plus_header* header = (s7plus_header*) (data + offset);
    header->data_length = ntohs(header->data_length);
    offset += 4;

    data_offset = offset;
    offset += header->data_length;

    return header;
}

s7plus_trailer* S7_Comm_Plus_Analyzer::ParseTrailer(const u_char* data)
{
    s7plus_trailer* trailer = (s7plus_trailer*) (data + offset);
    trailer->data_length = ntohs(trailer->data_length);

    return trailer;
}

void S7_Comm_Plus_Analyzer::ParseData(const u_char* data, s7plus_header* header, s7plus_trailer* trailer)
{
    u_char* op_code;
    u_int16* function_code;
    u_int16* sequence_number;
    u_int32* session_number;
    std::string packet_type = "";

    RecordVal* header_rec = 0;
    RecordVal* trailer_rec = 0;
    Args vl;
    EventHandlerPtr ev = 0;

    op_code = (u_char*) (data + data_offset);
    data_offset += 1;

    if((short)*op_code == S7COMMP_OPCODE_NOTIFICATION)
    {
        packet_type = "Notification";
        ev = s7p_notification;
    }
    else
    {
        data_offset += 2; // Skip unknown bytes;

        function_code = (u_int16*) (data + data_offset);
        data_offset += 2;
        data_offset += 2; // Skip another 2 unknown bytes
        sequence_number = (u_int16*) (data + data_offset);
        data_offset += 2;

        if((short)*op_code == S7COMMP_OPCODE_REQ)
        {
            packet_type = "Request";
            session_number = (u_int32*) (data + data_offset);
            data_offset += 4;

            data_offset += 1; // Skip unknown byte

            switch(ntohs(*function_code))
            {
                case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                {
                    ev = s7p_get_multi_variables;
                    ParseGetMultiVariablesReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                {
                    ev = s7p_set_multi_variables;
                    ParseSetMultiVariablesReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                {
                    ev = s7p_set_variable;
                    ParseSetVariableReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_CREATEOBJECT:
                {
                    ev = s7p_create_object;
                    ParseCreateObjectReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                {
                    ev = s7p_delete_object;
                    ParseDeleteObjectReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_GETVARSUBSTR:
                {
                    ev = s7p_get_var_substr;
                    ParseGetVarSubStreamedReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_EXPLORE:
                {
                    ev = s7p_explore;
                    ParseExploreReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_GETLINK:
                {
                    ev = s7p_get_link;
                    ParseGetLinkReq(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_BEGINSEQUENCE:
                {
                    ev = s7p_begin_sequence;
                    ParseBeginSequenceReq(data);
                    break;
                }    
                case S7COMMP_FUNCTIONCODE_ENDSEQUENCE:
                {
                    ev = s7p_end_sequence;
                    ParseGetMultiVariablesReq(data);
                    break;
                }   
                case S7COMMP_FUNCTIONCODE_INVOKE:
                {
                    ev = s7p_invoke;
                    ParseInvokeReq(data);
                    break;
                } 
            }
        }
        else
        {
            packet_type = "Response";
            data_offset += 1; // Skip unknown byte

            switch(ntohs(*function_code))
            {
                case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                {   
                    ev = s7p_get_multi_variables;
                    ParseGetMultiVariablesRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                {
                    ev = s7p_set_multi_variables;
                    ParseSetMultiVariablesRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                {
                    ev = s7p_set_variable;
                    ParseSetVariableRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_CREATEOBJECT:
                {
                    ev = s7p_create_object;
                    ParseCreateObjectRes(header, data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                {
                    ev = s7p_delete_object;
                    ParseDeleteObjectRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_GETVARSUBSTR:
                {
                    ev = s7p_get_var_substr;
                    ParseGetVarSubStreamedRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_EXPLORE:
                {
                    ev = s7p_explore;
                    ParseExploreRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_GETLINK:
                {
                    ev = s7p_get_link;
                    ParseGetLinkRes(data);
                    break;
                }
                case S7COMMP_FUNCTIONCODE_BEGINSEQUENCE:
                {
                    ev = s7p_begin_sequence;
                    ParseBeginSequenceRes(data);
                    break;
                }    
                case S7COMMP_FUNCTIONCODE_ENDSEQUENCE:
                {
                    ev = s7p_end_sequence;
                    ParseGetMultiVariablesRes(data);
                    break;
                }   
                case S7COMMP_FUNCTIONCODE_INVOKE:
                {
                    ev = s7p_invoke;
                    ParseInvokeRes(data);
                    break;
                } 
            }
        }
    }

    header_rec = new RecordVal(BifType::Record::S7CommPlus::S7PHeader);
    trailer_rec = new RecordVal(BifType::Record::S7CommPlus::S7PTrailer);

    header_rec->Assign(0, val_mgr->Count(header->protocol_id));
    header_rec->Assign(1, val_mgr->Count(header->version));
    header_rec->Assign(2, val_mgr->Count(header->data_length));

    trailer_rec->Assign(0, val_mgr->Count(trailer->protocol_id));
    trailer_rec->Assign(1, val_mgr->Count(trailer->version));
    trailer_rec->Assign(2, val_mgr->Count(trailer->data_length));

    vl.emplace_back(ConnVal());
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(packet_type)});

    if((short)*op_code != S7COMMP_OPCODE_NOTIFICATION)
    {
        vl.emplace_back(val_mgr->Count(ntohs(*sequence_number)));
    }
    else
    {
        vl.emplace_back(val_mgr->Count(0));
    }

    if((short)*op_code == S7COMMP_OPCODE_REQ)
    {
        vl.emplace_back(val_mgr->Count(ntohl(*session_number)));
    }
    else
    {
        vl.emplace_back(val_mgr->Count(0));
    }
    
    vl.emplace_back(IntrusivePtr{AdoptRef{}, header_rec});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(HexToString((data + offset - header->data_length), header->data_length))});
    vl.emplace_back(IntrusivePtr{AdoptRef{}, trailer_rec});

    EnqueueConnEvent(ev, std::move(vl));
}

void S7_Comm_Plus_Analyzer::ParseNotification(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseGetMultiVariablesReq(const u_char* data)
{
    int octets = 0;
    u_int32 id_value;
    u_int32 item_count;
    u_int32 number_of_fields;
    u_int32 item_address_count;
    u_int32 id_number;

    id_value = ntohl(*((u_int32*)(data + data_offset)));
    data_offset += 4;
    item_count = GetVarUInt32(data, octets);
    data_offset += octets;

    if(id_value == 0x0)
    {
        number_of_fields = GetVarUInt32(data, octets);
        data_offset += octets;

        for(int i = 0; i < item_count; i++)
        {
            // TODO: Decode Item Address here
        }
    }
    else
    {
        item_address_count = GetVarUInt32(data, octets);
        data_offset += octets;

        for(int i = 0; i < item_address_count; i++)
        {
            id_number = GetVarUInt32(data, octets);
            data_offset += octets;
        }
    }
}

void S7_Comm_Plus_Analyzer::ParseSetMultiVariablesReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseSetVariableReq(const u_char* data)
{
    // To be filled
}   

void S7_Comm_Plus_Analyzer::ParseCreateObjectReq(const u_char* data)
{
    // As it looks like, in every CreateObject request, the first thing we read
    // is an item-value with an 32-bit id (the other ids are vlq).
    // After that, we read 4 unknown bytes, followd by the first object to decode

    int octets = 0;
    std::string context = "CreateObject Request";
    // Parse the 32-bit ID
    u_int32* id = (u_int32*)(data + data_offset);
    data_offset += 4;
    // Decode first item-value (usually UDINt with value 0)
    DecodeValue(data, context, true);
    // Skip another 4 bytes
    data_offset += 4;
    // Decode first object, which may contain further objects
    DecodeObject(data, context);
    // Again, skip the last 4 unknown bytes. Done!
    data_offset += 4;
}

void S7_Comm_Plus_Analyzer::ParseCreateObjectRes(s7plus_header* header, const u_char* data)
{
    // TODO: Generate event
    int octets = 0;
    std::vector<int> object_ids;
    std::string context = "CreateObject Response"; // To determine 'where' the object came from

    u_int64 return_value;
    u_char object_id_count;
    u_int32 object_id;

    return_value = GetVarUInt64(data, octets);
    data_offset += octets;
    object_id_count = (short)*((u_char*)(data + data_offset));
    data_offset += 1;

    for(int i = 0; i < (short)object_id_count; i++)
    {
        object_ids.push_back(GetVarUInt32(data, octets));
        data_offset += octets;
    }

    if(header->version == S7COMMP_PROTOCOLVERSION_1)
    {
        DecodeObject(data, context);
    }
}

void S7_Comm_Plus_Analyzer::DecodeRelation(const u_char* data, std::string context)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::DecodeValue(const u_char* data, std::string context, bool first_value)
{
     u_char* datatype_flags;
    u_char* datatype;
    u_int32 array_size = 1; // Single Value
    int array_size_octets = 0;
    u_int32 id_number;
    int id_octets = 0;
    u_int32 sparsearray_key;
    int octets = 0;

    RecordVal* info = 0;
    EventHandlerPtr ev = 0;
    Args vl;

    if(!first_value)
    {
        id_number = GetVarUInt32(data, id_octets);
        data_offset += id_octets;
    }

    datatype_flags = (u_char*)(data + data_offset);
    data_offset += 1;
    datatype = (u_char*)(data + data_offset);
    data_offset += 1;

    switch(*datatype_flags)
    {
        case S7COMMP_ARRAY:
        case S7COMMP_ADDRESS_ARRAY:
        {
            array_size = GetVarUInt32(data, array_size_octets);
            data_offset += array_size_octets;
            break;
        }
        case S7COMMP_SPARSE_ARRAY:
        {
            array_size = 999999;
            break;
        }
    }

    for(int i = 1; i <= array_size; i++)
    {
        if(*datatype_flags == S7COMMP_SPARSE_ARRAY)
        {
            sparsearray_key = GetVarUInt32(data, octets);
            data_offset += octets;

            if(sparsearray_key == 0)
            {
                break;
            }
        }

        info = new RecordVal(BifType::Record::S7CommPlus::S7PItemValueInfo);
        info->Assign(0, val_mgr->Count(*datatype_flags));
        info->Assign(1, val_mgr->Count(array_size));
        info->Assign(2, val_mgr->Count(i));
        info->Assign(3, IntrusivePtr{AdoptRef{}, new StringVal(context)});
        info->Assign(4, val_mgr->Count(*datatype));

        switch(*datatype)
        {
            case S7COMMP_ITEM_DATATYPE_NULL:
            {
                break;
            }
            case S7COMMP_ITEM_DATATYPE_BOOL:
            {
                u_char* value = (u_char*)(data + data_offset);
                data_offset += 1;

                ev = s7p_item_value_bool;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Bool((short)*value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_USINT:
            {
                u_char* value = (u_char*)(data + data_offset);
                data_offset += 1;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count((short)*value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_UINT:
            {
                u_int16* value = (u_int16*)(data + data_offset);
                data_offset += 2;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohs(*value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_UDINT:
            {
                int octets = 0;
                u_int32 value = GetVarUInt32(data, octets);
                data_offset += octets;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_ULINT:
            {
                int octets = 0;
                u_int32 value = GetVarUInt64(data, octets);
                data_offset += octets;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_LINT:
            {
                int octets = 0;
                int64 value = GetVarInt64(data, octets);
                data_offset += octets;

                ev = s7p_item_value_int;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Int(value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_SINT:
            {
                u_char* value = (u_char*)(data + data_offset);
                data_offset += 1;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count((short)*value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_INT:
            {
                u_int16* value = (u_int16*)(data + data_offset);
                data_offset += 2;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohs(*value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_DINT:
            {
                int octets = 0;
                int32 value = GetVarInt32(data, octets);
                data_offset += octets;

                ev = s7p_item_value_int;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Int(value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_BYTE:
            {
                u_char* value = (u_char*)(data + data_offset);
                data_offset += 1;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count((short)*value));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_WORD:
            {
                u_int16* value = (u_int16*)(data + data_offset);
                data_offset += 2;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohs(*value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_STRUCT:
            {
                u_int32* value = (u_int32*)(data + data_offset);
                data_offset += 4;
                context = context + " | Struct value: " + std::to_string(ntohl(*value));

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohl(*value)));

                EnqueueConnEvent(ev, vl);

                DecodeValueList(data, context);
                break;
            }
            case S7COMMP_ITEM_DATATYPE_DWORD:
            {
                u_int32* value = (u_int32*)(data + data_offset);
                data_offset += 4;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohl(*value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_LWORD:
            {
                u_int64* value = (u_int64*)(data + data_offset);
                data_offset += 8;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntoh64(*value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_REAL:
            {
                std::string value = HexToString(data + data_offset, 4);
                data_offset += 4;

                ev = s7p_item_value_double;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Int(RealToFloat(value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_LREAL:
            {
                std::string value = HexToString(data + data_offset, 8);
                data_offset += 8;

                ev = s7p_item_value_double;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Int(RealToFloat(value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_TIMESTAMP:
            {
                u_int64* timestamp = (u_int64*)(data + data_offset);
                std::string timestamp_str = TimestampToString(ntoh64(*timestamp));

                ev = s7p_item_value_string;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(timestamp_str)});

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_TIMESPAN:
            {
                int octets = 0;
                int64 value = GetVarInt64(data, octets);
                data_offset += octets;
                std::string timespan = TimespanToString(ntoh64(value));

                ev = s7p_item_value_string;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(timespan)});

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_RID:
            {
                u_int32* value = (u_int32*)(data + data_offset);
                data_offset += 4;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohl(*value)));  

                EnqueueConnEvent(ev, vl);  

                break;
            }
            case S7COMMP_ITEM_DATATYPE_AID:
            {
                int octets = 0;
                u_int32 value = GetVarUInt32(data, octets);
                data_offset += octets;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohl(value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_WSTRING:
            {
                int octets = 0;
                u_int32 length = GetVarUInt32(data, octets);
                data_offset += octets;
                std::string value = HexToASCII(data + data_offset, length);
                data_offset += length;

                ev = s7p_item_value_string;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(value)});

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_VARIANT:
            {
                int octets = 0;
                u_int32 value = GetVarUInt32(data, octets);
                data_offset += octets;

                ev = s7p_item_value_count;
                vl.emplace_back(ConnVal());
                vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                vl.emplace_back(val_mgr->Count(ntohl(value)));

                EnqueueConnEvent(ev, vl);

                break;
            }
            case S7COMMP_ITEM_DATATYPE_BLOB:
            {
                int octets = 0;
                u_int32 blobsize;
                u_int32 blob_root_id;
                std::string value;

                blob_root_id = GetVarUInt32(data, octets);
                data_offset += octets;

                if(blob_root_id > 0)
                {
                    data_offset += 9;
                    context = context + " | Blob Root ID: " + std::to_string(blob_root_id);

                    ev = s7p_item_value_count;
                    vl.emplace_back(ConnVal());
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                    vl.emplace_back(val_mgr->Count(blob_root_id));

                    EnqueueConnEvent(ev, vl);

                    DecodeValueList(data, context);
                }
                else
                {
                    blobsize = GetVarUInt32(data, octets);
                    data_offset += octets;
                    value = HexToString(data + data_offset, blobsize);
                    data_offset += blobsize;

                    ev = s7p_item_value_string;
                    vl.emplace_back(ConnVal());
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, info});
                    vl.emplace_back(IntrusivePtr{AdoptRef{}, new StringVal(value)});

                    EnqueueConnEvent(ev, vl);
                }
                break;
            }
            default:
            {
                break;
            }
        }
    }
}

void S7_Comm_Plus_Analyzer::DecodeValueList(const u_char* data, std::string context)
{
    u_int32 id_number;
    int octets = 0;
    bool terminate = false;
    do
    {
        // Lookahead ID Number...
        id_number = GetVarUInt32(data, octets);

        if(id_number == 0)
        {
            terminate = true;
        }
        else
        {
            DecodeValue(data, context, false);
        }
    } while(!terminate);
}

void S7_Comm_Plus_Analyzer::DecodeObject(const u_char* data, std::string context)
{
    bool terminate = false;
    u_char* element_id;

    // Variables used by element_id == 0xa1
    int relation_id;
    int class_id;
    int octets = 0;
    int class_flags;
    int attribute_id;
    int attribute_flags; // if attribute_id != 0

    do 
    {
        element_id = (u_char*)(data + data_offset);
        data_offset += 1;

        switch(*element_id)
        {
            case S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT:     // 0xa1
            {
                relation_id = (int)*((u_int32*)(data + data_offset));
                data_offset += 4;
                class_id = GetVarUInt32(data, octets);;
                data_offset += octets;
                class_flags = GetVarInt32(data, octets);
                data_offset += octets;
                attribute_id = GetVarUInt32(data, octets);
                data_offset += octets;

                if(attribute_id != 0)
                {
                    attribute_flags = GetVarUInt32(data, octets);
                    data_offset += octets;
                }
                if(context != "")
                {
                    context = context + " | Object Class ID: " + std::to_string(class_id) + ", Relation ID: " + std::to_string(ntohl(relation_id));
                }
                DecodeObject(data, context);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_TERMOBJECT:      // 0xa2
            {
                terminate = true;
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_ATTRIBUTE:       // 0xa3
            {
                DecodeValue(data, context, false);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_RELATION:        // 0xa4
            {
                DecodeRelation(data, context);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_STARTTAGDESC:    // 0xa7
            {
                SkipToNextElementID(data);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_TERMTAGDESC:     // 0xa8
            {
                SkipToNextElementID(data);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_VARNAMELIST:     // 0xac
            {
                SkipToNextElementID(data);
                break;
            }
            case S7COMMP_ITEMVAL_ELEMENTID_VARTYPELIST:     // 0xab
            {
                SkipToNextElementID(data);
                break;
            }
            default:
            {
                terminate = true;
            }
        }
    } while(terminate != true);
}

void S7_Comm_Plus_Analyzer::ParseDeleteObjectReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseGetVarSubStreamedReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseExploreReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseGetLinkReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseBeginSequenceReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseEndSequenceReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseInvokeReq(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseGetMultiVariablesRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseSetMultiVariablesRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseSetVariableRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseDeleteObjectRes(const u_char* data)
{
    // To be filled
}   

void S7_Comm_Plus_Analyzer::ParseGetVarSubStreamedRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseExploreRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseGetLinkRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseBeginSequenceRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseEndSequenceRes(const u_char* data)
{
    // To be filled
}

void S7_Comm_Plus_Analyzer::ParseInvokeRes(const u_char* data)
{
    // To be filled
}

std::string S7_Comm_Plus_Analyzer::HexToString(const unsigned char* data, int length)
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

std::string S7_Comm_Plus_Analyzer::HexToASCII(const unsigned char* data, int length)
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

std::string S7_Comm_Plus_Analyzer::TimestampToString(uint64_t timestamp)
{
    u_int16 nanosec, microsec, millisec;
    struct tm *mt;
    time_t t;
    char timestamp_str[128];
    static const char mon_names[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    nanosec = timestamp % 1000;
    timestamp /= 1000;
    microsec = timestamp % 1000;
    timestamp /= 1000;
    millisec = timestamp % 1000;
    timestamp /= 1000;
    t = timestamp;
    mt = gmtime(&t);

    if (mt != NULL) {
        snprintf(timestamp_str, 128, "%s %2d, %d %02d:%02d:%02d.%03d.%03d.%03d", 
        mon_names[mt->tm_mon], mt->tm_mday, mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec, millisec, microsec, nanosec);
    }

    return std::string(timestamp_str);
}

std::string S7_Comm_Plus_Analyzer::TimespanToString(uint64_t timespan)
{
    char sval[8];
    int64 divs[] = { 86400000000000LL, 3600000000000LL, 60000000000LL, 1000000000LL, 1000000LL, 1000LL, 1LL};
    char const *vfmt[] = { "%dd", "%02dh", "%02dm", "%02ds", "%03dms", "%03dus", "%03dns"};
    int64 val;
    int i;
    char timespan_str[129];

    if (timespan == 0) {
        strncpy(timespan_str, "LT#000ns", 128);
        return "";
    }

    if (timespan < 0) {
        strncpy(timespan_str, "LT#-", 128);
        timespan *= -1;
    } else {
        strncpy(timespan_str, "LT#", 128);
    }

    for (i = 0; i < 7; i++) {
        val = timespan / divs[i];
        timespan -= val * divs[i];
        if (val > 0) {
            snprintf(sval, 8, vfmt[i], (int32)val);
            strncat(timespan_str, sval, 128);
            if (timespan > 0) {
                strncat(timespan_str, "_", 128);
            }
        }
    }

    return std::string(timespan_str);
}

// Copied from the s7commplus source code written by Thomas Wiens
// and modified to use it in Bro
// Function to calculate the value and number of octets of a vlq-integer (unsigned, 64-bit)
int S7_Comm_Plus_Analyzer::GetVarUInt64(const unsigned char* data, int& octets)
{
    int counter;
    uint64_t val = 0;
    short octet;
    short cont;
    int func_offset = data_offset;

    for(counter = 1; counter <=8; counter++)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;
        val <<= 7;
        cont = octet & 0x80;
        octet &= 0x7f;
        val += octet;
        if(cont == 0)
        {
            break;
        }
    }
    octets = counter;
    if(cont)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;
        val <<= 8;
        val += octet;
    }
    return val;
}

// Copied from the s7commplus source code written by Thomas Wiens
// and modified to use it in Bro
// Function to calculate the value and number of octets of a vlq-integer (signed, 64-bit)
int S7_Comm_Plus_Analyzer::GetVarInt64(const unsigned char* data, int& octets)
{
    int counter;
    int64_t val = 0;
    short octet;
    short cont;
    int func_offset = data_offset;

    for(counter = 1; counter <=8; counter++)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;

        if((counter == 1) && (octet &0x40))
        {
            octet &= 0xbf;
            val = 0xffffffffffffffc0; 
        }
        else
        {
            val <<= 7;
        }
        cont = octet & 0x80;
        octet &= 0x7f;
        val += octet;
        if(cont == 0)
        {
            break;
        }
    }
    octets = counter;
    if(cont)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;
        val <<= 8;
        val += octet;
    }
    return val;
}

// Copied from the s7commplus source code written by Thomas Wiens
// and modified to use it in Bro
// Function to calculate the value and number of octets of a vlq-integer (unsigned, 32-bit)
int S7_Comm_Plus_Analyzer::GetVarUInt32(const unsigned char* data, int& octets)
{
    int counter;
    u_int32_t val = 0;
    short octet;
    short cont;
    int func_offset = data_offset;

    for(counter = 1; counter <= 4+1; counter++)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;
        val <<= 7;
        cont = octet & 0x80;
        octet &= 0x7f;
        val += octet;
        if(cont == 0) // More octets?
        {
            break;
        }
    }
    octets = counter;
    return val;
}

// Copied from the s7commplus source code written by Thomas Wiens
// and modified to use it in Bro
// Function to calculate the value and number of octets of a vlq-integer (signed, 32-bit)
int S7_Comm_Plus_Analyzer::GetVarInt32(const unsigned char* data, int& octets)
{
    int counter;
    int32_t val = 0;
    short octet;
    short cont;
    int func_offset = data_offset;

    for(counter = 1; counter <= 4+1; counter++)
    {
        octet = (short)*((u_char*)(data + func_offset));
        func_offset += 1;

        if((counter == 1) && (octet &0x40)) // Sign bit set?
        {
            octet &= 0xbf;
            val = 0xffffffc0; // Einerkomplement, lasse jedoch die letzten 6 Bits aus (c0)
        }
        else
        {
            val <<= 7;
        }
        cont = octet & 0x80;
        octet &= 0x7f;
        val += octet;
        if(cont == 0)
        {
            break;
        }
    }
    octets = counter;
    return val;
}

uint64_t S7_Comm_Plus_Analyzer::ntoh64(const uint64_t input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;

    return rval;
}

// For now I can only handle element-ids 0xa1 (object), 0xa3 (attribute) and 0xa4 (relation),
// because I don't have any significant data or pcaps for the other ids (0xa7, 0xa8, 0xab and 0xac).
// So anytime I'm seeing an element id that is different from 0xa1, 0xa3 or 0xa4, I'm skipping all
// bytes until I see something familiar.
void S7_Comm_Plus_Analyzer::SkipToNextElementID(const u_char* data)
{
    u_char* next_byte = (u_char*)(data + data_offset);

    while(*next_byte != 0xa1 || *next_byte != 0xa3 || *next_byte != 0xa4 )
    {
        data_offset += 1;
        next_byte = (u_char*)(data + data_offset); 
    }

    return;
}

float S7_Comm_Plus_Analyzer::RealToFloat(std::string data)
{
    real_to_float_union u;
    std::stringstream ss(data);
    ss >> std::hex >> u.ul;
    float f = u.f;
    return f;
}
