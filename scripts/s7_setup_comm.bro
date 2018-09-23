module S7Comm_Setup;

export {

    global job_set: count;
    global ack_set: count;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        max_amq_calling: count &log;
        max_amq_caller: count &log;
        pdu_length: count &log;
    };
}

event bro_init() &priority=5
{
    job_set = 0;
    ack_set = 0;
    Log::create_stream(S7Comm_Setup::LOG, [$columns=Info, $path="s7_setup_comm"]);
}

event s7_job_setup_communication(c: connection, header: S7Comm::S7Header, param: S7Comm::S7SetupCommParam)
{
    job_set += 1;
    Log::write(S7Comm_Setup::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $rosctr="Job", $max_amq_calling=param$maxamqcalling, $max_amq_caller=param$maxamqcaller, $pdu_length=param$pdulength]);
}

event s7_ackdata_setup_communication(c: connection, header: S7Comm::S7Header, param: S7Comm::S7SetupCommParam)
{
    ack_set += 1;
    local rec: S7Comm_Setup::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $rosctr="AckData", $max_amq_calling=param$maxamqcalling, $max_amq_caller=param$maxamqcaller, $pdu_length=param$pdulength];
    Log::write(S7Comm_Setup::LOG, rec);
}