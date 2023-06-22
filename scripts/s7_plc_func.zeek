module S7Comm_PLC_Func;

export {

    redef enum Log::ID += { LOG };

    global job_plc_control: count;
    global ack_plc_control: count;
    global job_plc_stop: count;
    global ack_plc_stop: count;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        service: string &log &optional;
        block: string_vec &log &optional;
        filename: string &log &optional;
    };
}

event zeek_init() &priority=5
{
    job_plc_control = 0;
    ack_plc_control = 0;
    job_plc_stop = 0;
    ack_plc_stop = 0;

    Log::create_stream(S7Comm_PLC_Func::LOG, [$columns=Info, $path="s7_plc_func"]);
}

event s7_job_plc_control(c: connection, header:S7Comm::S7Header, service: string, blocks: count, fields: count, block: string_vec)
{
    job_plc_control += 1;

    local rec: S7Comm_PLC_Func::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="Job PLC Control",
                                        $service=service,
                                        $block=block];

    Log::write(S7Comm_PLC_Func::LOG, rec);
}

event s7_ackdata_plc_control(c: connection, header:S7Comm::S7Header)
{
    ack_plc_control += 1;
    
    local rec: S7Comm_PLC_Func::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="AckData PLC Control"];

    Log::write(S7Comm_PLC_Func::LOG, rec);
}

event s7_job_plc_stop(c: connection, header:S7Comm::S7Header, filename: string)
{
    job_plc_stop += 1;
    
    local rec: S7Comm_PLC_Func::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="Job PLC Stop",
                                        $filename=filename];

    Log::write(S7Comm_PLC_Func::LOG, rec);
}

event s7_ackdata_plc_stop(c: connection, header:S7Comm::S7Header)
{
    ack_plc_stop += 1;
    
    local rec: S7Comm_PLC_Func::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="AckData PLC Stop"];

    Log::write(S7Comm_PLC_Func::LOG, rec);
}