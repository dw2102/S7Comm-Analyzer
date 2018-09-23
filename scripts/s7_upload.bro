module S7Comm_Upload;

export {

    global job_start_upload: count;
    global job_upload: count;
    global job_end_upload: count;

    global ack_start_upload: count;
    global ack_upload: count;
    global ack_end_upload: count;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        status: count &log &optional;
        upload_id: count &log &optional;
        filename: string &log &optional;
        data_length: count &log &optional;
        data: string &log &optional;
        error_code: count &log &optional;
    };
}

event bro_init() &priority=5
{
    job_start_upload = 0;
    job_upload = 0;
    job_end_upload = 0;
    ack_start_upload = 0;
    ack_upload = 0;
    ack_end_upload = 0;

    Log::create_stream(S7Comm_Upload::LOG, [$columns=Info, $path="s7_upload"]);
}

event s7_job_start_upload(c: connection, header:S7Comm::S7Header, param: S7Comm::S7JobStartUpload)
{
    job_start_upload += 1;

    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="Job Start Upload",
                                      $status=param$func_status,
                                      $upload_id=param$upload_id,
                                      $filename=param$filename];

    Log::write(S7Comm_Upload::LOG, rec);
}
event s7_ackdata_start_upload(c: connection, header:S7Comm::S7Header, param: S7Comm::S7AckDataStartUpload)
{
    ack_start_upload += 1;

    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="AckData Start Upload",
                                      $status=param$func_status,
                                      $upload_id=param$upload_id];

    Log::write(S7Comm_Upload::LOG, rec);
}

event s7_job_upload(c: connection, header:S7Comm::S7Header, func_status: count, upload_id: count)
{
    job_upload += 1;

    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="Job Upload",
                                      $status=func_status,
                                      $upload_id=upload_id];

    Log::write(S7Comm_Upload::LOG, rec);
}

event s7_ackdata_upload(c: connection, header:S7Comm::S7Header, func_status: count, data_length: count, data: string)
{
    ack_upload += 1;
    
    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="AckData Upload",
                                      $status=func_status,
                                      $data_length=data_length,
                                      $data=data];

    Log::write(S7Comm_Upload::LOG, rec);
}

event s7_job_end_upload(c: connection, header:S7Comm::S7Header, func_status: count, error_code: count, upload_id: count)
{
    job_end_upload += 1;
    
    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="Job End Upload",
                                      $upload_id=upload_id,
                                      $error_code=error_code];

    Log::write(S7Comm_Upload::LOG, rec);
}

event s7_ackdata_end_upload(c: connection, header:S7Comm::S7Header)
{
    ack_end_upload += 1;
    
    local rec: S7Comm_Upload::Info = [$ts=network_time(), 
                                      $uid=c$uid, 
                                      $id=c$id, 
                                      $rosctr="AckData End Upload"];

    Log::write(S7Comm_Upload::LOG, rec);
}