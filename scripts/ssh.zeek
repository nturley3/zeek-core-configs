##! Extracts and logs variable names from cookies sent by clients.

# @load base/protocols/ssh/main

module SSH;

redef record SSH::Info += {
    ## Extending the SSH log to faciliate authentication threat hunting.
    ## This has been done until Humio supports proper query joins with the
    ## conn.log
    orig_bytes: count &log &optional;
    resp_bytes: count &log &optional;
    missed_bytes: count &log &optional;
    orig_ip_bytes: count &log &optional;
    resp_ip_bytes: count &log &optional;
};


# TODO: This works, but doesn't contain the total count of bytes (fires too early)
event ssh_auth_attempted(c: connection, authenticated: bool) &priority=10
{
    if(! c?$ssh)
    {
        return;
    }
    #print(c$conn);
    #print("======");
    c$ssh$orig_bytes = c$orig$size;
#    c$ssh$resp_bytes = c$conn$resp_bytes;
#    c$ssh$missed_bytes = c$conn$missed_bytes;
#    c$ssh$orig_ip_bytes = c$conn$orig_ip_bytes;
#    c$ssh$resp_ip_bytes = c$conn$orig_ip_bytes;
    #print(c$ssh);
    #print("======");
}

event SSH::log_ssh(rec: SSH::Info)
{
    print(rec);
    print("=====");
}

#event connection_state_remove(c: connection) &priority=1000
#{
#    if(! c?$ssh)
#    {
#        return;
#    }
#    #print(c$conn);
#    #print("======");
#    c$ssh$orig_bytes = c$orig$size;
##    c$ssh$resp_bytes = c$conn$resp_bytes;
##    c$ssh$missed_bytes = c$conn$missed_bytes;
##    c$ssh$orig_ip_bytes = c$conn$orig_ip_bytes;
##    c$ssh$resp_ip_bytes = c$conn$orig_ip_bytes;
#    print(c$ssh);
#    print("======");
#}
