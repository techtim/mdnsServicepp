#include "mdnsService.h"

int
main()
{
    mdns::MdnsService service;
    service.start("_http._tcp.local.", "Hello");
    service.discover();
    service.sendMdnsQuery("_http._tcp.local.");
    while (1) {
        ;
    }
    exit(0);
}