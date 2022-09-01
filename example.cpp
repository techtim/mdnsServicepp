#include "mdnsService.h"

int
main()
{
    mdns::MdnsService service;
    auto txts = mdns::TxtRecordArray{std::make_pair("mac", "13:13:13:13"), std::make_pair("enttec", "S-Play")};
    service.start("_http._tcp.local.", "Hello", txts);
    service.discover();
    service.sendMdnsQuery("_http._tcp.local.");
    while (1) {
        ;
    }
    exit(0);
}