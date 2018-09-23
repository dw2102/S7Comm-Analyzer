module S7Comm_Read;

export {

    global item_table: table[count] of count;
    global item_table_ack: table[count] of count;
    global read_count: count;
    global read_count_ack: count;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        item_no: count &log;
        items: count &log;
        syntax_id: string &log &optional;
        return_code: count &log &optional;
    };
}

function reassable_read_items(pdu_ref: count, items: count)
{
    if(items <= 1)
    {
        read_count += 1;
        return;
    }

    if(pdu_ref in item_table)
    {
        item_table[pdu_ref] -= 1;
        if(item_table[pdu_ref] == 0)
        {
            delete item_table[pdu_ref];
            read_count += 1;
        }
    }
    else
    {
        item_table[pdu_ref] = items - 1;
    }
}

function reassable_read_items_ack(pdu_ref: count, items: count)
{
    if(items <= 1)
    {
        read_count_ack += 1;
        return;
    }

    if(pdu_ref in item_table_ack)
    {
        item_table_ack[pdu_ref] -= 1;
        if(item_table_ack[pdu_ref] == 0)
        {
            delete item_table_ack[pdu_ref];
            read_count_ack += 1;
        }
    }
    else
    {
        item_table_ack[pdu_ref] = items - 1;
    }
}

event bro_init() &priority=5
{
    read_count = 0;
    read_count_ack = 0;
    Log::create_stream(S7Comm_Read::LOG, [$columns=Info, $path="s7_read"]);
}

event s7_job_read_variable_any_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7AnyTypeItem)
{
    reassable_read_items(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Job Read",  
                                    $item_no=item_num,
                                    $items=items,
                                    $syntax_id="Any"];

    Log::write(S7Comm_Read::LOG, rec);
}

event s7_job_read_variable_db_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7DBTypeItem)
{
    reassable_read_items(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Job Read",  
                                    $item_no=item_num,
                                    $items=items,
                                    $syntax_id="DB"];

    Log::write(S7Comm_Read::LOG, rec);
}

event s7_job_read_variable_1200_sym_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S71200SymTypeItem)
{
    reassable_read_items(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Job Read",  
                                    $item_no=item_num,
                                    $items=items,
                                    $syntax_id="SYM"];

    Log::write(S7Comm_Read::LOG, rec);

}

event s7_job_read_variable_nck_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7NCKTypeItem)
{
    reassable_read_items(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Job Read", 
                                    $item_no=item_num, 
                                    $items=items,
                                    $syntax_id="NCK"];

    Log::write(S7Comm_Read::LOG, rec);
}

event s7_job_read_variable_drive_any_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7DriveAnyTypeItem)
{
    reassable_read_items(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="Job Read", 
                                    $item_no=item_num, 
                                    $items=items,
                                    $syntax_id="DriveANY"];

    Log::write(S7Comm_Read::LOG, rec);
}

event s7_ackdata_read_data(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7ReadWriteData)
{
    reassable_read_items_ack(header$pdu_ref, items);

    local rec: S7Comm_Read::Info = [$ts=network_time(), 
                                    $uid=c$uid, 
                                    $id=c$id, 
                                    $rosctr="AckData Read", 
                                    $item_no=item_num, 
                                    $items=items,
                                    $return_code=item$error_code];

    Log::write(S7Comm_Read::LOG, rec);
}