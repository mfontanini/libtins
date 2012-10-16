#include <iostream>
#include <map>
#include <string>
#include <tins/tins.h>

using namespace Tins;

class BeaconSniffer {
public:
    void run(const std::string &iface);
private:
    typedef Dot11::address_type address_type;
    typedef std::map<address_type, std::string> ssids_type;

    bool callback(PDU &pdu);
    
    ssids_type ssids;
};

void BeaconSniffer::run(const std::string &iface) {
    Sniffer sniffer(iface, 1500, true, "type mgt subtype beacon");
    sniffer.sniff_loop(make_sniffer_handler(this, &BeaconSniffer::callback));
}

bool BeaconSniffer::callback(PDU &pdu) {
    Dot11Beacon *beacon = pdu.find_pdu<Dot11Beacon>();
    if(beacon && !beacon->from_ds() && !beacon->to_ds()) {
        address_type addr = beacon->addr2();
        ssids_type::iterator it = ssids.find(addr);
        if(it == ssids.end()) {
            try {
                it = ssids.insert(std::make_pair(addr, beacon->ssid())).first;
                std::cout << it->first << " - " << it->second << std::endl;
            }
            catch(std::runtime_error&) {
                // no ssid, just ignore it.
            }
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    std::string interface = "wlan0";
    if(argc == 2)
        interface = argv[1];
    BeaconSniffer sniffer;
    sniffer.run(interface);
}
