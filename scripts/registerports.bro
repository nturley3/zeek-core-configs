##! This forces Bro to try using the HTTP analyzer on a port
##! that Bro doesn't by default consider a cleartext HTTP 
##! port (i.e. SSL) and therefore the analyzer is never invoked.
##! This is needed to support SSL decrypt payload processing.
const extra_http_ports = { 443/tcp };

event bro_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, extra_http_ports);
}