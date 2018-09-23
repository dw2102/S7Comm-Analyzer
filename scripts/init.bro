#
# Init script for the ISO over TCP / S7Comm analyzer,
# mainly used to test the events with pcap files
# 
# Author: Dane Wullen
# Date: 10.04.2018
# Version: 1.0
# 
# This plugin is a part of a master's thesis written at Fachhochschule in Aachen (Aachen University of Applied Sciences)
# 
#

const ports = {102/tcp};

event bro_init()
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_ISO_OVER_TCP, ports);
}
