const ports = {102/tcp};

event zeek_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_ISO_OVER_TCP, ports);
}