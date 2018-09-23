module S7Comm_Write;

export {

    global item_table: table[count] of count;
    global item_table_ack: table[count] of count;
    global write_count: count;
    global write_count_ack: count;

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

function reassable_write_items(pdu_ref: count, items: count)
{
    if(items <= 1)
    {
        write_count += 1;
        return;
    }

    if(pdu_ref in item_table)
    {
        item_table[pdu_ref] -= 1;
        if(item_table[pdu_ref] == 0)
        {
            delete item_table[pdu_ref];
            write_count += 1;
        }
    }
    else
    {
        item_table[pdu_ref] = items - 1;
    }
}

function reassable_write_items_ack(pdu_ref: count, items: count)
{
    if(items <= 1)
    {
        write_count_ack += 1;
        return;
    }

    if(pdu_ref in item_table)
    {
        item_table_ack[pdu_ref] -= 1;
        if(item_table_ack[pdu_ref] == 0)
        {
            delete item_table_ack[pdu_ref];
            write_count_ack += 1;
        }
    }
    else
    {
        item_table_ack[pdu_ref] = items - 1;
    }
}

event bro_init() &priority=5
{
    write_count = 0;
    write_count_ack = 0;
    Log::create_stream(S7Comm_Write::LOG, [$columns=Info, $path="s7_write"]);
}

event s7_job_write_variable_any_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7AnyTypeItem, data: S7Comm::S7ReadWriteData)
{
    reassable_write_items(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="Job Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $syntax_id="Any",
                                     $return_code=data$error_code];

    Log::write(S7Comm_Write::LOG, rec);
}

event s7_job_write_variable_db_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7DBTypeItem, data: S7Comm::S7ReadWriteData)
{
    reassable_write_items(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="Job Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $syntax_id="DB",
                                     $return_code=data$error_code];

    Log::write(S7Comm_Write::LOG, rec);
}

event s7_job_write_variable_1200_sym_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S71200SymTypeItem, data: S7Comm::S7ReadWriteData)
{
    reassable_write_items(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="Job Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $syntax_id="SYM",
                                     $return_code=data$error_code];

    Log::write(S7Comm_Write::LOG, rec);
}

event s7_job_write_variable_nck_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7NCKTypeItem, data: S7Comm::S7ReadWriteData)
{
    reassable_write_items(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="Job Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $syntax_id="NCK",
                                     $return_code=data$error_code];

    Log::write(S7Comm_Write::LOG, rec);
}

event s7_job_write_variable_drive_any_type(c: connection, header: S7Comm::S7Header, items: count, item_num: count, item: S7Comm::S7DriveAnyTypeItem, data: S7Comm::S7ReadWriteData)
{
    reassable_write_items(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="Job Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $syntax_id="DriveES",
                                     $return_code=data$error_code];

    Log::write(S7Comm_Write::LOG, rec);
}

event s7_ackdata_write_data(c: connection, header: S7Comm::S7Header, items: count, item_num: count, return_code: count)
{
    reassable_write_items_ack(header$pdu_ref, items);

    local rec: S7Comm_Write::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $rosctr="AckData Write",  
                                     $item_no=item_num,
                                     $items=items,
                                     $return_code=return_code];

    Log::write(S7Comm_Write::LOG, rec);
}