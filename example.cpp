#include "mdnsService.h"

int
main()
{
    mdns::MdnsService service;
    auto txts = mdns::TxtRecordArray{std::make_pair("mac", "13:13:13:13:13:13"),
                                     std::make_pair("enttec", "S-Play asdasdjsa;ldj alkdsjlsa djsalkdjsakld")};
    service.start("_http._tcp.local.", "Hello", txts);
    service.discover();
    auto discovered = service.sendMdnsQuery("_http._tcp.local.");
    for (const auto &res : discovered) {
        std::cout << "MdnsQuery Result: " << mdns::ipv4_address_to_string(&res.ipv4) << " service=" << res.service
                  << " hostname=" << res.hostname << " txt records: ";
        for (const auto &txt : res.txt_records)
            std::cout << txt.first << "=" << txt.second << ";";
        std::cout << std::endl;
    }

    while (1) {
        ;
    }
    exit(0);
}