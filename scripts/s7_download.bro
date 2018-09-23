module S7Comm_Download;

export {

    global job_request_download: count;
    global job_download: count;
    global job_end_download: count;

    global ack_request_download: count;
    global ack_download: count;
    global ack_end_download: count;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        rosctr: string &log;
        status:	count &log &optional;
		filename: string &log &optional;
        data_length: count &log &optional;
        error_code: count &log &optional;
    };
}

event bro_init() &priority=5
{
    job_request_download = 0;
    job_download = 0;
    job_end_download = 0;
    ack_request_download = 0;
    ack_download = 0;
    ack_end_download = 0;

    Log::create_stream(S7Comm_Download::LOG, [$columns=Info, $path="s7_download"]);
}

event s7_job_request_download(c: connection, header:S7Comm::S7Header, param: S7Comm::S7JobRequestDownload)
{
    job_request_download += 1;

    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="Job Request Download",
                                        $status=param$func_status,
                                        $filename=param$filename];

    Log::write(S7Comm_Download::LOG, rec);
}

event s7_ackdata_request_download(c: connection, header:S7Comm::S7Header)
{
    ack_request_download += 1;
    
    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="AckData Request Download"];

    Log::write(S7Comm_Download::LOG, rec);
}

event s7_job_download_block(c: connection, header:S7Comm::S7Header, param: S7Comm::S7JobDownloadBlock)
{
    job_download += 1;
    
    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="Job Download Block",
                                        $status=param$func_status,
                                        $filename=param$filename];

    Log::write(S7Comm_Download::LOG, rec);
}

event s7_ackdata_download_block(c: connection, header:S7Comm::S7Header, func_status: count, param: S7Comm::S7AckDataDownloadBlock)
{
    ack_download += 1;
    
    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="AckData Download Block",
                                        $status=func_status,
                                        $data_length=param$data_length];

    Log::write(S7Comm_Download::LOG, rec);
}

event s7_job_download_ended(c: connection, header:S7Comm::S7Header, param: S7Comm::S7JobDownloadEnded)
{
    job_end_download += 1;
    
    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="Job Download Ended",
                                        $status=param$func_status,
                                        $filename=param$filename,
                                        $error_code=param$error_code];

    Log::write(S7Comm_Download::LOG, rec);
}

event s7_ackdata_download_ended(c: connection, header:S7Comm::S7Header)
{
    ack_end_download += 1;
    
    local rec: S7Comm_Download::Info = [$ts=network_time(), 
                                        $uid=c$uid, 
                                        $id=c$id, 
                                        $rosctr="AckData Download Ended"];

    Log::write(S7Comm_Download::LOG, rec);
}