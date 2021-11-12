## Extend the NTLM log to record the NTLM and LM negotiation flags
module ExtendNTLM;
export
{
    # Reference: https://www.gaijin.at/en/infos/windows-version-numbers
    type ExtendNTLM::winversion: record {
        major: count &optional &log;
        minor: count &optional &log;
        build: count &optional &log;
        ntlmssp: count &optional &log;
    };
}
## Extend the NTLM record. Add NTLM, LM and extenses session security flags
## https://docs.zeek.org/en/lts/script-reference/proto-analyzers.html#type-NTLM::NegotiateFlags
redef record NTLM::Info += {
    negotiate_extended_sessionsecurity: bool &optional &log;
    negotiate_ntlm: bool &optional &log;
    negotiate_lm_key: bool &optional &log;
    winversion: ExtendNTLM::winversion &optional &log;
};
event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
    local winver: ExtendNTLM::winversion;
    # Record the NTLM and LM negotiation flags if detected
    if(c?$ntlm && ! c$ntlm?$negotiate_extended_sessionsecurity && request$flags?$negotiate_extended_sessionsecurity)
    {
        c$ntlm$negotiate_extended_sessionsecurity = request$flags$negotiate_extended_sessionsecurity;
    }
    if(c?$ntlm && ! c$ntlm?$negotiate_ntlm && request$flags?$negotiate_ntlm)
    {
        c$ntlm$negotiate_ntlm = request$flags$negotiate_ntlm;
    }
    if(c?$ntlm && ! c$ntlm?$negotiate_lm_key && request$flags?$negotiate_lm_key)
    {
        c$ntlm$negotiate_lm_key = request$flags$negotiate_lm_key;
    }
    # Record the OS version information detected in the NTLM session
    if(c?$ntlm && ! c$ntlm?$winversion && request?$version)
    {
        winver$major = request$version?$major ? request$version$major : 0;
        winver$minor = request$version?$minor ? request$version$minor : 0;
        winver$build = request$version?$build ? request$version$build : 0;
        winver$ntlmssp = request$version?$ntlmssp ? request$version$ntlmssp : 0;
        c$ntlm$winversion = winver;
    }
}