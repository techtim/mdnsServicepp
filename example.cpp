#include "mdnsService.h"

int
main()
{
    mdns::MdnsService service;
    service.start("_http._tcp.local.", "Hello");
    service.discover();

    while (1) {
        ;
        ;
    }
    exit(0);
}