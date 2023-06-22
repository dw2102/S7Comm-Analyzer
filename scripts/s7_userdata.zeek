@load ./s7_const

module S7_UserData;

export {

    global unknown_packets: count;
    global func_group_1: count;
    global func_group_2: count;
    global func_group_3: count;
    global func_group_4: count;
    global func_group_5: count;
    global func_group_6: count;
    global func_group_7: count;
    global func_group_15: count;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        packet_type: string &log;
    };
}

event zeek_init() &priority=5
{
    unknown_packets = 0;
    func_group_1 = 0;
    func_group_2 = 0;
    func_group_3 = 0;
    func_group_4 = 0;
    func_group_5 = 0;
    func_group_6 = 0;
    func_group_7 = 0;
    func_group_15 = 0;

    Log::create_stream(S7_UserData::LOG, [$columns=Info, $path="s7_userdata"]);
} 

event s7_ud_prog_reqdiagdata1(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDReqDiagData)
{
    func_group_1 += 1;

    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Programmer commands: Request Diag Data 1",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_prog_reqdiagdata2(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDReqDiagData)
{
    func_group_1 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Programmer commands: Request Diag Data 2",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_prog_vartab1_request(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDVarTab1ReqData)
{
    func_group_1 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Programmer commands: Vartab 1",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_prog_vartab1_response(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDVarTab1ResData)
{
    func_group_1 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Programmer commands: Vartab 1",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_prog_unknown(c: connection, header:S7Comm::S7Header, packet_type: string, subfunction: count, data: S7Comm::S7UDUnknownData)
{
    func_group_1 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Programmer commands: %s", S7_Const::subfunction_names_group_1[subfunction]),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_any(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, interval_timebase: count, interval_time: count, item: S7Comm::S7AnyTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read Any",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_db(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, interval_timebase: count, interval_time: count, item: S7Comm::S7DBTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read DB",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_sym(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, interval_timebase: count, interval_time: count, item: S7Comm::S71200SymTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read SYM",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_nck(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, interval_timebase: count, interval_time: count, item: S7Comm::S7NCKTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read NCK",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_drive(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, interval_timebase: count, interval_time: count, item: S7Comm::S7DriveAnyTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read DriveAnyES",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_ack(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, item: S7Comm::S7ReadWriteData)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read Ack",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_mem_ack_nck(c: connection, header:S7Comm::S7Header, packet_type: string, return_code: count, transport_size: count, items: count, item_num: count, item: S7Comm::S7NCKTypeItem)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Read Ack NCK",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cycl_unsub(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDUnknownData)
{
    func_group_2 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Cyclic Data: Unsub",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_block_list_res(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDBlockList)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Block functions: List Blocks",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);   
}

event s7_ud_block_listtype_req(c: connection, header:S7Comm::S7Header, packet_type: string, return_value: count, transport_size: count, data_length: count, data: string)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Block functions: List blocks of Type '%s'", data),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec); 
}

event s7_ud_block_listtype_res(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDBlockList)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Block functions: List blocks of Type",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec); 
}

event s7_ud_block_blockinfo_req(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDBlockInfoReq)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Block functions: Get Block Info",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec); 
}

event s7_ud_block_blockinfo_res(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDBlockInfoRes)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Block functions: Get Block Info",
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec); 
}

event s7_ud_block_unknown(c: connection, header:S7Comm::S7Header, packet_type: string, subfunction: count, data: S7Comm::S7UDUnknownData)
{
    func_group_3 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Block functions: %s", S7_Const::subfunction_names_group_3[subfunction]),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cpu_read_szl(c: connection, header:S7Comm::S7Header, packet_type: string, szl_id: string, szl_index: string)
{
    func_group_4 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("CPU functions: Read SZL"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_cpu_unknown(c: connection, header:S7Comm::S7Header, packet_type: string, subfunction: count, data: S7Comm::S7UDUnknownData)
{
    func_group_4 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("CPU functions: %s", S7_Const::subfunction_names_group_4[subfunction]),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_security(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDUnknownData)
{
    func_group_5 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Security functions: Password"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_pbc(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDPBC)
{
    func_group_6 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Programmable Block Communication function"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_time_read(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDTime)
{
    func_group_7 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Time functions: Read Time"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_time_readf(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDTime)
{
    func_group_7 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Time functions: Read Time"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_time_set1(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDTime)
{
    func_group_7 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Time functions: Set(1) Time"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_time_set2(c: connection, header:S7Comm::S7Header, packet_type: string, data: S7Comm::S7UDTime)
{
    func_group_7 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Time functions: Set(2) Time"),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_time_unknown(c: connection, header:S7Comm::S7Header, packet_type: string, subfunction: count, data: S7Comm::S7UDUnknownData)
{
    func_group_7 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("Time functions: %s", S7_Const::subfunction_names_group_7[subfunction]),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}

event s7_ud_ncprog(c: connection, header:S7Comm::S7Header, packet_type: string, subfunction: count, data: S7Comm::S7UDUnknownData)
{
    func_group_15 += 1;
    
    local rec: S7_UserData::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr=fmt("NC Programming functions: %s", S7_Const::subfunction_names_group_15[subfunction]),
                                    $packet_type=packet_type];

    Log::write(S7_UserData::LOG, rec);
}