# Header only C++ wrapper for domain mDNS/DNS-SD library in C

This library provides a header only modern C++11 wrapper for cross-platform mDNS and DNS-DS C library:
https://github.com/mjansson/mdns

Inspired by https://github.com/gocarlos/mdns_cpp, just provides cleaner interface for sending mDNS Queries in more C++ fashion.

## Features
The library does DNS-SD `discover()` service in separate thread. 
As well as customized `sendMdnsQuery` with response returned as vector<QueryResult>

## Build
After clone run: `git submodule update --init`

Example provided in example.cpp can be build:
```
cmake -S . -B build/ -DMDNSSERVICE_BUILD_EXAMPLE=ON
cd build 
make
./mdnsServicepp_example
```

## Usage 
Include mdnsServise.h
Class MdnsServise implements mdns.c logic.