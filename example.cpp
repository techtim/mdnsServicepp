#include "mdnsService.h"

int
main()
{
    mdns::MdnsService service;
    service.start("_http._tcp.local.", "Hello",
                  {std::make_pair("mac", "13:13:13:13"), std::make_pair("enttec", "S-Play")});
    service.discover();
    service.sendMdnsQuery("_http._tcp.local.");
    while (1) {
        ;
    }
    exit(0);
}