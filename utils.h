#pragma once

#include <string>
#include <map>
#include <functional>

#include "include/mdns/mdns.h"

namespace mdns {

using std::string;

static inline string
ipv4_address_to_string(const struct sockaddr_in *addr)
{
    string ip{inet_ntoa(addr->sin_addr)};
    if (addr->sin_port != 0)
        ip.append(":").append(std::to_string(addr->sin_port));
    return ip;
}

static inline string
ipv6_address_to_string(const struct sockaddr_in6 *addr)
{
    string ip(INET6_ADDRSTRLEN, ' ');
    inet_ntop(AF_INET6, &(addr->sin6_addr), ip.data(), INET6_ADDRSTRLEN);
    if (addr->sin6_port != 0)
        ip.append(":").append(std::to_string(addr->sin6_port));
    return ip;
}

static inline string
ip_address_to_string(const struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET6)
        return ipv6_address_to_string((const struct sockaddr_in6 *)addr);
    return ipv4_address_to_string((const struct sockaddr_in *)addr);
}

static inline string
recordtype_to_string(mdns_record_type rtype)
{
    switch (rtype) {
        case MDNS_RECORDTYPE_PTR:
            return "PTR";
        case MDNS_RECORDTYPE_SRV:
            return "SRV";
        case MDNS_RECORDTYPE_A:
            return "A";
        case MDNS_RECORDTYPE_AAAA:
            return "AAAA";
        case MDNS_RECORDTYPE_TXT:
            return "TXT";
        case MDNS_RECORDTYPE_ANY:
            return "ANY";
        default:
            return "";
    }
}

static inline string
entrytype_to_string(mdns_entry_type_t entry)
{
    switch (entry) {
        case MDNS_ENTRYTYPE_ANSWER:
            return "answer";
        case MDNS_ENTRYTYPE_AUTHORITY:
            return "authority";
        case MDNS_ENTRYTYPE_ADDITIONAL:
            return "additional";
        default:
            return "question";
    }
}

static inline bool
isEqual(mdns_string_t const &lhs, mdns_string_t const &rhs)
{
    return lhs.length == rhs.length && strncmp(lhs.str, rhs.str, lhs.length) == 0;
}

template <typename T>
struct CallbackQuery;

template <typename Ret, typename... Params>
struct CallbackQuery<Ret(Params...)> {
    template <typename... Args>
    static Ret callback(Args... args)
    {
        return func(args...);
    }
    static std::function<Ret(Params...)> func;
};

template <typename Ret, typename... Params>
std::function<Ret(Params...)> CallbackQuery<Ret(Params...)>::func;

template <typename T>
struct CallbackService;

template <typename Ret, typename... Params>
struct CallbackService<Ret(Params...)> {
    template <typename... Args>
    static Ret callback(Args... args)
    {
        return func(args...);
    }
    static std::function<Ret(Params...)> func;
};

template <typename Ret, typename... Params>
std::function<Ret(Params...)> CallbackService<Ret(Params...)>::func;

} // namespace mdns