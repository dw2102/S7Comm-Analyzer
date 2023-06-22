module S7CommPlusAll;

export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        packet_type: string &log;
        func: string &log;
    };
}

event zeek_init() &priority=5
{
    Log::create_stream(S7CommPlusAll::LOG, [$columns=Info, $path="s7p_everything"]);
}

function write_log(c: connection, packet_type: string, func: string)
{
    local rec: S7CommPlusAll::Info = [$ts=network_time(), 
                                     $uid=c$uid, 
                                     $id=c$id, 
                                     $packet_type=packet_type,
                                     $func=func];

    Log::write(S7CommPlusAll::LOG, rec);
}

event s7p_notification(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, packet_type);
}

event s7p_explore(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Explore");
}

event s7p_create_object(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Create Object");
}

event s7p_delete_object(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Delete Object");
}

event s7p_set_variable(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Set Variable");
}

event s7p_get_link(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Get Link");
}

event s7p_set_multi_variables(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Set Multi Variables");
}

event s7p_get_multi_variables(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Get Multi Variables");
}

event s7p_begin_sequence(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Begin Sequence");
}

event s7p_end_sequence(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "End Sequence");
}

event s7p_invoke(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Invoke");
}

event s7p_get_var_substr(c: connection, packet_type: string, sequence_number: count, session_id: count, header:S7CommPlus::S7PHeader, data: string, trailer: S7CommPlus::S7PTrailer)
{
    write_log(c, packet_type, "Get Var Substr");
}


