#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#else

#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>

#endif

#include <iostream>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <array>

#include "utils.h"
#include "include/mdns/mdns.h"

namespace mdns {

using std::to_string;

static constexpr size_t s_txtRecordsNum = 2;
using TxtRecordArray = std::array<std::pair<string, string>, s_txtRecordsNum>;

static constexpr size_t s_maxSocketsNum = 32;
static constexpr size_t s_bufferCapacity = 2048;
static const string s_dnsSd = "_services._dns-sd._udp.local.";
static const mdns_string_t s_dns_sd{s_dnsSd.c_str(), s_dnsSd.length()};

struct ServiceState {
    mdns_string_t service;
    mdns_string_t hostname;
    mdns_string_t service_instance;
    mdns_string_t hostname_qualified;
    sockaddr_in address_ipv4;
    sockaddr_in6 address_ipv6;
    uint16_t port;
    mdns_record_t record_ptr;
    mdns_record_t record_srv;
    mdns_record_t record_a;
    mdns_record_t record_aaaa;
    mdns_record_t txt_record[s_txtRecordsNum];
};

struct QueryResult {
    string hostname;
    string service;
    sockaddr_in ipv4{};
    sockaddr_in6 ipv6{};
    TxtRecordArray txt_records;
};

inline std::ostream &
operator<<(std::ostream &os, const QueryResult &res)
{
    os << "QueryResult hostname=" << res.hostname << " service=" << res.service
       << " ipv4=" << ipv4_address_to_string(&res.ipv4, false) << " ipv6=" << ipv6_address_to_string(&res.ipv6)
       << " txt records: [ ";
    for (const auto &txt : res.txt_records)
        os << "'" << txt.first << "'='" << txt.second << "' ";
    os << "]";
    return os;
}

struct open_sockets_res {
    int num_sockets;
    sockaddr_in service_address_ipv4;
    sockaddr_in6 service_address_ipv6;
};

class MdnsService {
public:
    explicit MdnsService(std::function<void(const std::string &)> logCallback = nullptr)
    {
        generateMdnsRecordCallbacks();

        if (logCallback != nullptr)
            logger_callback = std::move(logCallback);
    }

    void discover()
    {
        send_dns_sd();
    }

    std::vector<QueryResult> sendMdnsQuery(const string &serviceName, mdns_record_type type = MDNS_RECORDTYPE_ANY)
    {
        mdns_query_t query{type, serviceName.c_str(), serviceName.length()};
        return send_mdns_query(std::vector<mdns_query_t>{query});
    }

    std::vector<QueryResult> sendMdnsQuery(std::vector<mdns_query_t> queries)
    {
        return send_mdns_query(std::move(queries));
    }

    void start(const string &serviceName, const string &hostname, TxtRecordArray txt_records = {},
               uint16_t port = MDNS_PORT)
    {
        stop();
        m_isRunning = true;
        m_serviceThread = std::thread([this, txt_records, hostname, serviceName, port]() {
            this->service_mdns(hostname, serviceName, txt_records, port);
        });
    }

    void stop()
    {
        m_isRunning = false;
        if (m_serviceThread.joinable()) {
            m_serviceThread.join();
        }
    }

    ~MdnsService()
    {
        stop();
    }
    MdnsService(MdnsService &&) = delete;
    MdnsService(const MdnsService &) = delete;

private:
    char entrybuffer[256];
    char namebufferQuery[256];
    char namebufferService[256];
    char sendbuffer[256];
    mdns_record_txt_t txtbuffer[128];

    std::function<void(const std::string &)> logger_callback = [](const std::string &str) {
        static std::mutex logLock;
        std::lock_guard<std::mutex> lock(logLock);
        std::cout << str << std::endl;
    };

    std::thread m_serviceThread;
    std::atomic<bool> m_isRunning;
    mdns_record_callback_fn m_mdns_query_callback, m_mdns_service_callback;

    /// Port of mdns.cpp logic
    int query_callback(int sock, const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id,
                       uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset,
                       size_t name_length, size_t record_offset, size_t record_length, void *user_data)
    {
        (void)sizeof(sock);
        (void)sizeof(addrlen);
        (void)sizeof(query_id);
        (void)sizeof(name_length);
        (void)sizeof(user_data);

        auto userDataQueryResult = static_cast<QueryResult *>(user_data);

        string fromAddrstr = ip_address_to_string(from);
        string entrytype = entrytype_to_string(entry);
        mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
        string fromEntry =
            fromAddrstr.append(" type=").append(entrytype).append(" entry=").append(entrystr.str, entrystr.length);

        if (rtype == MDNS_RECORDTYPE_PTR) {
            mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, namebufferQuery,
                                                          sizeof(namebufferQuery));
            userDataQueryResult->service.append(entrystr.str, entrystr.length);
            logger_callback(string("PTR: ")
                                .append(fromEntry)
                                .append(" name=")
                                .append(namestr.str, namestr.length)
                                .append(" rclass=")
                                .append(to_string(rclass))
                                .append(" ttl=")
                                .append(to_string(ttl)));
        }
        else if (rtype == MDNS_RECORDTYPE_SRV) {
            mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, namebufferQuery,
                                                          sizeof(namebufferQuery));
            userDataQueryResult->hostname.append(srv.name.str, srv.name.length);
            logger_callback(string("SRV: ")
                                .append(fromEntry)
                                .append(" name=")
                                .append(srv.name.str, srv.name.length)
                                .append(" priority=")
                                .append(to_string(srv.priority))
                                .append(" weight=")
                                .append(to_string(srv.weight))
                                .append(" port=")
                                .append(to_string(srv.port)));
        }
        else if (rtype == MDNS_RECORDTYPE_A) {
            sockaddr_in addr;
            mdns_record_parse_a(data, size, record_offset, record_length, &addr);
            auto addrstr = ipv4_address_to_string(&addr);
            userDataQueryResult->ipv4 = addr;
            logger_callback(string("A: ").append(fromEntry).append(" address:").append(addrstr));
        }
        else if (rtype == MDNS_RECORDTYPE_AAAA) {
            sockaddr_in6 addr;
            mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
            userDataQueryResult->ipv6 = addr;
            logger_callback(
                string("AAAA: ").append(fromEntry).append(" address:").append(ipv6_address_to_string(&addr)));
        }
        else if (rtype == MDNS_RECORDTYPE_TXT) {
            size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
                                                  sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
            for (size_t itxt = 0; itxt < parsed; ++itxt) {
                auto key = string(txtbuffer[itxt].key.str, txtbuffer[itxt].key.length);
                auto value = string(txtbuffer[itxt].value.str, txtbuffer[itxt].value.length);
                logger_callback(string(to_string(itxt))
                                    .append(" TXT: ")
                                    .append(fromEntry)
                                    .append(" key=")
                                    .append(key)
                                    .append(" value=")
                                    .append(value));
                if (itxt < userDataQueryResult->txt_records.size()) {
                    userDataQueryResult->txt_records.at(itxt) = std::make_pair(key, value);
                }
            }
        }
        else {
            logger_callback(string(to_string(rtype))
                                .append("OTHER :")
                                .append(fromEntry)
                                .append(" rclass=")
                                .append(to_string(rclass))
                                .append(" ttl=")
                                .append(to_string(ttl)));
        }
        return 0;
    }

    // Callback handling questions incoming on service sockets
    int service_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                         uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                         size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                         size_t record_length, void *user_data)
    {
        (void)sizeof(ttl);
        (void)sizeof(name_length);
        (void)sizeof(record_offset);
        (void)sizeof(record_length);

        if (entry != MDNS_ENTRYTYPE_QUESTION)
            return 0;

        auto service = (const ServiceState *)user_data;

        auto fromaddrstr = ip_address_to_string(from);

        size_t offset = name_offset;
        mdns_string_t name = mdns_string_extract(data, size, &offset, namebufferService, sizeof(namebufferService));

        auto record_type = static_cast<mdns_record_type>(rtype);
        auto record_type_name = recordtype_to_string(record_type);
        logger_callback(string("Query type=").append(record_type_name).append(" name=").append(name.str, name.length));

        if (record_type_name.empty())
            return 0;

        uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);

        if (isEqual(name, s_dns_sd)) {
            if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
                // The PTR query was for the DNS-SD domain, send answer with a PTR record for the
                // service name we advertise, typically on the "<_service-name>._tcp.local." format

                mdns_record_t answer = {name, MDNS_RECORDTYPE_PTR, {mdns_record_ptr_t{service->service}}, 0, 0};

                logger_callback(string("  --> answer for DNS-SD: ")
                                    .append(answer.data.ptr.name.str, answer.data.ptr.name.length)
                                    .append(" - ")
                                    .append(unicast ? "unicast" : "multicast")
                                    .append(" to ")
                                    .append(ip_address_to_string(from)));

                if (unicast) {
                    mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                              record_type, name.str, name.length, answer, nullptr, 0, nullptr, 0);
                }
                else {
                    mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, nullptr, 0, nullptr, 0);
                }
            }
        }
        else if (isEqual(name, service->service)) {
            if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
                // The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
                // record reverse mapping the queried service name to our service instance name
                // (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
                // additional records containing the SRV record mapping the service instance name to our
                // qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
                // address for the hostname as A/AAAA records, and two test TXT records

                std::vector<mdns_record_t> additional = generateAdditionalRecords(*service);

                logger_callback(string("  --> answer for record PTR: ")
                                    .append(service->record_ptr.name.str, service->record_ptr.name.length)
                                    .append(" - ")
                                    .append(unicast ? "unicast" : "multicast")
                                    .append(" to ")
                                    .append(ip_address_to_string(from)));

                if (unicast) {
                    mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                              record_type, name.str, name.length, service->record_ptr, nullptr, 0,
                                              additional.data(), additional.size());
                }
                else {
                    mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), service->record_ptr, nullptr, 0,
                                                additional.data(), additional.size());
                }
            }
        }
        else if (isEqual(name, service->service_instance)) {
            if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
                // The SRV query was for our service instance (usually
                // "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
                // instance name to our qualified hostname (typically "<hostname>.local.") and port, as
                // well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
                // records

                auto additional = generateAdditionalRecords(*service);

                logger_callback(string("  --> answer for record SRV: ")
                                    .append(service->record_srv.name.str, service->record_srv.name.length)
                                    .append(" - ")
                                    .append(unicast ? "unicast" : "multicast")
                                    .append(" to ")
                                    .append(ip_address_to_string(from)));

                if (unicast) {
                    mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                              record_type, name.str, name.length, service->record_srv, nullptr, 0,
                                              additional.data(), additional.size());
                }
                else {
                    mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), service->record_srv, nullptr, 0,
                                                additional.data(), additional.size());
                }
            }
        }
        else if (isEqual(name, service->hostname_qualified)) {
            if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
                (service->address_ipv4.sin_family == AF_INET)) {
                // The A query was for our qualified hostname (typically "<hostname>.local.") and we
                // have an IPv4 address, answer with an A record mapping the hostname to an IPv4
                // address, as well as any IPv6 address for the hostname, and two test TXT records
                // Answer A records mapping "<hostname>.local." to IPv4 address

                std::vector<mdns_record_t> additional = generateAdditionalRecords(*service);

                logger_callback(string("  --> answer for qualified hostname: ")
                                    .append(service->record_a.name.str, service->record_a.name.length)
                                    .append(" IPv4=")
                                    .append(ipv4_address_to_string(&service->record_a.data.a.addr))
                                    .append(unicast ? " unicast" : " multicast"));

                if (unicast) {
                    mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                              record_type, name.str, name.length, service->record_a, nullptr, 0,
                                              additional.data(), additional.size());
                }
                else {
                    mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), service->record_a, nullptr, 0,
                                                additional.data(), additional.size());
                }
            }
            else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
                     (service->address_ipv6.sin6_family == AF_INET6)) {
                // The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
                // have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
                // address, as well as any IPv4 address for the hostname, and two test TXT records
                // Answer AAAA records mapping "<hostname>.local." to IPv6 address

                std::vector<mdns_record_t> additional = generateAdditionalRecords(*service);

                logger_callback(string("  --> answer for qualified hostname: ")
                                    .append(service->record_aaaa.name.str, service->record_aaaa.name.length)
                                    .append(" IPv6=")
                                    .append(ipv6_address_to_string(&service->record_aaaa.data.aaaa.addr))
                                    .append(unicast ? " unicast" : " multicast"));

                if (unicast) {
                    mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                              record_type, name.str, name.length, service->record_aaaa, nullptr, 0,
                                              additional.data(), additional.size());
                }
                else {
                    mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), service->record_aaaa, nullptr, 0,
                                                additional.data(), additional.size());
                }
            }
        }
        return 0;
    }

    // Open sockets for sending one-shot multicast queries from an ephemeral port
    open_sockets_res open_client_sockets(int *sockets, int max_sockets, int port)
    {
        // When sending, each socket can only send to one network interface
        // Thus we need to open one socket for each interface and address family
        open_sockets_res res{0, {}, {}};

#ifdef _WIN32

        IP_ADAPTER_ADDRESSES *adapter_address = 0;
        ULONG address_size = 8000;
        unsigned int ret;
        unsigned int num_retries = 4;
        do {
            adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
            ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapter_address,
                                       &address_size);
            if (ret == ERROR_BUFFER_OVERFLOW) {
                free(adapter_address);
                adapter_address = 0;
                address_size *= 2;
            }
            else {
                break;
            }
        } while (num_retries-- > 0);

        if (!adapter_address || (ret != NO_ERROR)) {
            free(adapter_address);
            logger_callback("Failed to get network adapter addresses");
            return res;
        }

        int first_ipv4 = 1;
        int first_ipv6 = 1;
        for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
            if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
                continue;
            if (adapter->OperStatus != IfOperStatusUp)
                continue;

            for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *saddr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                    if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
                        (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
                        int log_addr = 0;
                        if (first_ipv4) {
                            res.service_address_ipv4 = *saddr;
                            first_ipv4 = 0;
                            log_addr = 1;
                        }

                        if (res.num_sockets < max_sockets) {
                            saddr->sin_port = htons((unsigned short)port);
                            int sock = mdns_socket_open_ipv4(saddr);
                            if (sock >= 0) {
                                sockets[res.num_sockets++] = sock;
                                log_addr = 1;
                            }
                            else {
                                log_addr = 0;
                            }
                        }
                        if (log_addr) {
                            auto addr = ipv4_address_to_string(saddr);
                            logger_callback("Local IPv4 address: " + addr);
                        }
                    }
                }
                else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
                    // Ignore link-local addresses
                    if (saddr->sin6_scope_id)
                        continue;
                    static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                    static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                                                                     0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
                    if ((unicast->DadState == NldsPreferred) && memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                        memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                        int log_addr = 0;
                        if (first_ipv6) {
                            service_address_ipv6 = *saddr;
                            first_ipv6 = 0;
                            log_addr = 1;
                        }

                        if (res.num_sockets < max_sockets) {
                            saddr->sin6_port = htons((unsigned short)port);
                            int sock = mdns_socket_open_ipv6(saddr);
                            if (sock >= 0) {
                                sockets[res.num_sockets++] = sock;
                                log_addr = 1;
                            }
                            else {
                                log_addr = 0;
                            }
                        }
                        if (log_addr) {
                            auto addr = ipv6_address_to_string(saddr);
                            logger_callback("Local IPv6 address: " + addr);
                        }
                    }
                }
            }
        }

        free(adapter_address);

#else

        struct ifaddrs *ifaddr = nullptr;

        if (getifaddrs(&ifaddr) < 0)
            logger_callback("Unable to get interface addresses");

        int first_ipv4 = 1;
        int first_ipv6 = 1;
        for (auto ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr)
                continue;
            if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
                continue;
            if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
                continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                auto saddr = (struct sockaddr_in *)ifa->ifa_addr;
                if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                    int log_addr = 0;
                    if (first_ipv4) {
                        res.service_address_ipv4 = *saddr;
                        first_ipv4 = 0;
                        log_addr = 1;
                    }

                    if (res.num_sockets < max_sockets) {
                        saddr->sin_port = htons(port);
                        int sock = mdns_socket_open_ipv4(saddr);
                        if (sock >= 0) {
                            sockets[res.num_sockets++] = sock;
                            log_addr = 1;
                        }
                        else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        auto addr = ipv4_address_to_string(saddr);
                        logger_callback(string("Open client socket on local IPv4 address: ").append(addr));
                    }
                }
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6) {
                auto saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
                // Ignore link-local addresses
                if (saddr->sin6_scope_id)
                    continue;
                static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
                if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                    int log_addr = 0;
                    if (first_ipv6) {
                        res.service_address_ipv6 = *saddr;
                        first_ipv6 = 0;
                        log_addr = 1;
                    }

                    if (res.num_sockets < max_sockets) {
                        saddr->sin6_port = htons(port);
                        int sock = mdns_socket_open_ipv6(saddr);
                        if (sock >= 0) {
                            sockets[res.num_sockets++] = sock;
                            log_addr = 1;
                        }
                        else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        auto addr = ipv6_address_to_string(saddr);
                        logger_callback(string("Open client socket on IPv6 address: ").append(addr));
                    }
                }
            }
        }

        freeifaddrs(ifaddr);

#endif

        return res;
    }

    // Open sockets to listen to incoming mDNS queries on port 5353
    open_sockets_res open_service_sockets(int *sockets, int max_sockets)
    {
        // When recieving, each socket can recieve data from all network interfaces
        // Thus we only need to open one socket for each address family
        int num_sockets = 0;

        // Call the client socket function to enumerate and get local addresses,
        // but not open the actual sockets
        auto res = open_client_sockets(nullptr, 0, 0);

        if (num_sockets < max_sockets) {
            sockaddr_in sock_addr;
            memset(&sock_addr, 0, sizeof(struct sockaddr_in));
            sock_addr.sin_family = AF_INET;
#ifdef _WIN32
            sock_addr.sin_addr = in4addr_any;
#else
            sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
            sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
            sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
            int sock = mdns_socket_open_ipv4(&sock_addr);
            if (sock >= 0)
                sockets[num_sockets++] = sock;
        }

        if (num_sockets < max_sockets) {
            sockaddr_in6 sock_addr;
            memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
            sock_addr.sin6_family = AF_INET6;
            sock_addr.sin6_addr = in6addr_any;
            sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
            sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
            int sock = mdns_socket_open_ipv6(&sock_addr);
            if (sock >= 0)
                sockets[num_sockets++] = sock;
        }

        res.num_sockets = num_sockets;
        return res;
    }

    // Send a DNS-SD query
    int send_dns_sd()
    {
        int sockets[s_maxSocketsNum];
        auto open_res = open_client_sockets(sockets, s_maxSocketsNum, 0);
        if (open_res.num_sockets <= 0) {
            logger_callback("Failed to open any client sockets");
            return -1;
        }
        logger_callback(string("Opened for DNS-SD socket(s): ").append(to_string(open_res.num_sockets)));

        logger_callback("Sending DNS-SD discovery");

        for (int isock = 0; isock < open_res.num_sockets; ++isock) {
            if (mdns_discovery_send(sockets[isock]) != 0)
                logger_callback(string("Failed to send DNS-DS discovery:").append(strerror(errno)));
        }

        std::shared_ptr<void> buffer(malloc(s_bufferCapacity), free);
        QueryResult userDataEntry;
        void *user_data = &userDataEntry;
        size_t records;

        // This is a simple implementation that loops for 5 seconds or as long as we get replies
        int res;
        logger_callback("Reading DNS-SD replies");
        do {
            timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                if (sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            records = 0;
            res = select(nfds, &readfs, nullptr, nullptr, &timeout);
            if (res > 0) {
                for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                    if (FD_ISSET(sockets[isock], &readfs)) {
                        records += mdns_discovery_recv(sockets[isock], buffer.get(), s_bufferCapacity,
                                                       m_mdns_query_callback, user_data);
                    }
                }
            }
        } while (res > 0);

        logger_callback(string("DNS-SD discovered: ").append(to_string(records)));

        for (int isock = 0; isock < open_res.num_sockets; ++isock)
            mdns_socket_close(sockets[isock]);

        logger_callback(string("Closed for DNS-SD socket(s): ").append(to_string(open_res.num_sockets)));

        return 0;
    }

    // Send a mDNS query
    std::vector<QueryResult> send_mdns_query(std::vector<mdns_query_t> queries)
    {
        std::vector<QueryResult> discoveredDevice;

        int sockets[s_maxSocketsNum];
        int query_id[s_maxSocketsNum];
        auto open_res = open_client_sockets(sockets, s_maxSocketsNum, 0);
        if (open_res.num_sockets <= 0) {
            logger_callback("Failed to open any client sockets\n");
            return discoveredDevice;
        }
        logger_callback(string("Opened for mDNS query socket(s):").append(to_string(open_res.num_sockets)));

        std::shared_ptr<void> buffer(malloc(s_bufferCapacity), free);

        logger_callback("Sending mDNS queries:");
        for (size_t iq = 0; iq < queries.size(); ++iq) {
            auto record_name = recordtype_to_string(queries.at(iq).type);
            if (record_name.empty()) {
                queries.at(iq).type = MDNS_RECORDTYPE_PTR;
                record_name = "PTR";
            }
            logger_callback(string("-Query name=").append(queries.at(iq).name).append(" type=").append(record_name));
        }

        for (int isock = 0; isock < open_res.num_sockets; ++isock) {
            logger_callback(string("Send multiquery for socket: ").append(to_string(sockets[isock])));
            query_id[isock] =
                mdns_multiquery_send(sockets[isock], queries.data(), queries.size(), buffer.get(), s_bufferCapacity, 0);
            if (query_id[isock] < 0)
                logger_callback(string("Failed to send mDNS query: ").append(strerror(errno)));
        }

        // This is a simple implementation that loops for 5 seconds or as long as we get replies
        int res;
        logger_callback("Reading mDNS query replies\n");
        int records = 0;
        do {
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                if (sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            res = select(nfds, &readfs, 0, 0, &timeout);
            if (res > 0) {
                for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                    if (FD_ISSET(sockets[isock], &readfs)) {
                        QueryResult userDataQueryResult;
                        void *user_data = &userDataQueryResult;
                        auto rec = mdns_query_recv(sockets[isock], buffer.get(), s_bufferCapacity,
                                                   m_mdns_query_callback, user_data, query_id[isock]);
                        if (rec > 0) {
                            discoveredDevice.emplace_back(std::move(userDataQueryResult));
                        }
                    }
                    FD_SET(sockets[isock], &readfs);
                }
            }
        } while (res > 0);

        logger_callback(string("Read records: ").append(to_string(records)));

        for (int isock = 0; isock < open_res.num_sockets; ++isock) {
            mdns_socket_close(sockets[isock]);
        }
        logger_callback(string("Closed for mDNS query socket(s): ").append(to_string(open_res.num_sockets)));

        return discoveredDevice;
    }

    // Provide a mDNS service, answering incoming DNS-SD and mDNS queries
    int service_mdns(const string &hostname, string service_name, TxtRecordArray txt_records,
                     uint16_t service_port = MDNS_PORT)
    {
        int sockets[s_maxSocketsNum];
        auto open_res = open_service_sockets(sockets, s_maxSocketsNum);
        if (open_res.num_sockets <= 0) {
            logger_callback("Failed to open any client sockets");
            return -1;
        }

        logger_callback(string("Opened for mDNS service socket(s):")
                            .append(to_string(open_res.num_sockets))
                            .append(" IPv4:")
                            .append(ipv4_address_to_string(&open_res.service_address_ipv4))
                            .append(" IPv6:")
                            .append(ipv6_address_to_string(&open_res.service_address_ipv6)));

        if (service_name.empty()) {
            logger_callback("Invalid service name");
            return -1;
        }

        if (service_name.back() != '.')
            service_name.append(".");

        logger_callback(string("Service mDNS: ").append(service_name).append(":").append(to_string(service_port)));
        logger_callback("Hostname: " + hostname);

        auto service_instance = string(hostname).append(".").append(service_name);
        auto hostname_qualified = string(hostname).append(".local.");

        ServiceState service;
        service.service = {service_name.c_str(), service_name.length()};
        service.hostname = {hostname.c_str(), hostname.length()};
        service.service_instance = {service_instance.c_str(), service_instance.length()};
        service.hostname_qualified = {hostname_qualified.c_str(), hostname_qualified.length()};
        service.address_ipv4 = open_res.service_address_ipv4;
        service.address_ipv6 = open_res.service_address_ipv6;
        service.port = service_port;

        // Setup our mDNS records

        // PTR record reverse mapping "<_service-name>._tcp.local." to
        // "<hostname>.<_service-name>._tcp.local."
        service.record_ptr = {
            service.service, MDNS_RECORDTYPE_PTR, {mdns_record_ptr_t{service.service_instance}}, 0, 0};

        // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
        // "<hostname>.local." with port. Set weight & priority to 0.
        service.record_srv.name = service.service_instance;
        service.record_srv.type = MDNS_RECORDTYPE_SRV;
        service.record_srv.data.srv = {0, 0, service.port, service.hostname_qualified};
        service.record_srv.rclass = 0;
        service.record_srv.ttl = 0;

        // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
        service.record_a.name = service.hostname_qualified;
        service.record_a.type = MDNS_RECORDTYPE_A;
        service.record_a.data.a.addr = service.address_ipv4;
        service.record_a.rclass = 0;
        service.record_a.ttl = 0;

        service.record_aaaa.name = service.hostname_qualified;
        service.record_aaaa.type = MDNS_RECORDTYPE_AAAA;
        service.record_aaaa.data.aaaa.addr = service.address_ipv6;
        service.record_aaaa.rclass = 0;
        service.record_aaaa.ttl = 0;

        // Add test TXT records for our service instance name, will be coalesced into
        // one record with both key-value pair strings by the library
        for (size_t irec = 0; irec < s_txtRecordsNum; ++irec) {
            service.txt_record[irec].name = service.service_instance;
            service.txt_record[irec].type = MDNS_RECORDTYPE_TXT;
            service.txt_record[irec].data.txt.key =
                mdns_string_t{txt_records.at(irec).first.c_str(), txt_records.at(irec).first.length()};
            service.txt_record[irec].data.txt.value =
                mdns_string_t{txt_records.at(irec).second.c_str(), txt_records.at(irec).second.length()};
            service.txt_record[irec].rclass = 0;
            service.txt_record[irec].ttl = 0;
        }

        std::shared_ptr<void> buffer(malloc(s_bufferCapacity), free);

        // Send an announcement on startup of service
        {
            logger_callback("Sending announce");
            std::vector<mdns_record_t> additional = generateAdditionalRecords(service);
            for (int isock = 0; isock < open_res.num_sockets; ++isock)
                mdns_announce_multicast(sockets[isock], buffer.get(), s_bufferCapacity, service.record_ptr, nullptr, 0,
                                        additional.data(), additional.size());
        }

        // This is a crude implementation that checks for incoming queries
        while (m_isRunning) {
            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                if (sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;

            if (select(nfds, &readfs, nullptr, nullptr, &timeout) >= 0) {
                for (int isock = 0; isock < open_res.num_sockets; ++isock) {
                    if (FD_ISSET(sockets[isock], &readfs)) {
                        mdns_socket_listen(sockets[isock], buffer.get(), s_bufferCapacity, m_mdns_service_callback,
                                           &service);
                    }
                    FD_SET(sockets[isock], &readfs);
                }
            }
            else {
                logger_callback("Error on check NFDS descriptors");
                break;
            }
        }

        // Send a goodbye on end of service
        {
            logger_callback("Sending goodbye");
            std::vector<mdns_record_t> additional = generateAdditionalRecords(service);

            for (int isock = 0; isock < open_res.num_sockets; ++isock)
                mdns_goodbye_multicast(sockets[isock], buffer.get(), s_bufferCapacity, service.record_ptr, nullptr, 0,
                                       additional.data(), additional.size());
        }

        for (int isock = 0; isock < open_res.num_sockets; ++isock)
            mdns_socket_close(sockets[isock]);

        logger_callback(string("Closed socket(s): ").append(to_string(open_res.num_sockets)));

        return 0;
    }

    static std::vector<mdns_record_t> generateAdditionalRecords(const ServiceState &service)
    {
        std::vector<mdns_record_t> additional;
        additional.push_back(service.record_srv);
        if (service.address_ipv4.sin_family == AF_INET)
            additional.push_back(service.record_a);
        if (service.address_ipv6.sin6_family == AF_INET6)
            additional.push_back(service.record_aaaa);
        for (size_t irec = 0; irec < s_txtRecordsNum; ++irec) {
            additional.push_back(service.txt_record[irec]);
        }
        return additional;
    }

    /// Callbacks init
    void generateMdnsRecordCallbacks()
    {
        using namespace std::placeholders;

#if defined(__APPLE__) || defined(_LIBCPP_FUNCTIONAL)
        constexpr __ph<11> _11;
        constexpr __ph<12> _12;
        constexpr __ph<13> _13;
        constexpr __ph<14> _14;
        constexpr __ph<15> _15;
#endif

        CallbackQuery<int(int, const sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t, uint16_t, uint32_t,
                          const void *, size_t, size_t, size_t, size_t, size_t, void *)>::func =
            std::bind(&MdnsService::query_callback, this, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,
                      _15);
        m_mdns_query_callback = static_cast<mdns_record_callback_fn>(
            CallbackQuery<int(int, const sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t, uint16_t, uint32_t,
                              const void *, size_t, size_t, size_t, size_t, size_t, void *)>::callback);

        CallbackService<int(int, const sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t, uint16_t, uint32_t,
                            const void *, size_t, size_t, size_t, size_t, size_t, void *)>::func =
            std::bind(&MdnsService::service_callback, this, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,
                      _15);

        m_mdns_service_callback = static_cast<mdns_record_callback_fn>(
            CallbackService<int(int, const sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t, uint16_t,
                                uint32_t, const void *, size_t, size_t, size_t, size_t, size_t, void *)>::callback);
    }
};

} // namespace mdns