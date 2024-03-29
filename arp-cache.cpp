/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"

#include <algorithm>
#include <iostream>

#include "core/interface.hpp"
#include "core/utils.hpp"
#include "simple-router.hpp"

namespace simple_router {

void ArpCache::handleArpRequests() {
    #ifdef FUNCNAME
    std::cerr << "handleArpRequests" << std::endl;
    #endif

    std::vector<std::shared_ptr<ArpRequest>> invalidRequests;
    for (auto request : m_arpRequests) {
        time_point now = steady_clock::now();
        if (now - request->timeSent <= seconds(1)) {
            CERR("Time interval < 1s, miss it");
            return;
        }

        if (request->nTimesSent >= MAX_SENT_TIME) {
            CERR("ARP attempts exceeded");
            invalidRequests.push_back(request);
            for (auto& packet : request->packets) {
                m_router.replyIcmpHostUnreachable(packet.packet);
            }
        } else {
            CERR("resend ARP attempts");
            // std::cerr << "target IP: " << ipToString(request->ip) << std::endl;
            m_router.sendArpRequest(request->ip);
            request->nTimesSent++;
            request->timeSent = now;
        }
    }

    for (auto request : invalidRequests) {
        m_arpRequests.remove(request);
    }
}

void ArpCache::removeInvalidEntries() {
    #ifdef FUNCNAME
    std::cerr << "removeInvalidEntries" << std::endl;
    #endif

    std::vector<std::shared_ptr<ArpEntry>> invalidEntries;
    for (auto entry : m_cacheEntries) {
        if (!entry->isValid) {
            invalidEntries.push_back(entry);
        }
    }
    for (auto entry : invalidEntries) {
        m_cacheEntries.remove(entry);
    }
    // std::remove_if(m_cacheEntries.begin(), m_cacheEntries.end(),
    //                [](const std::shared_ptr<ArpEntry>& entry) {
    //                    return !entry->isValid;
    //                });
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void ArpCache::periodicCheckArpRequestsAndCacheEntries() {
    // FILL THIS IN

    // #ifdef DEBUG
    // std::cerr << "\nMAC            IP         AGE                       VALID\n"
    //    << "-----------------------------------------------------------\n";

    // auto now = steady_clock::now();
    // for (const auto& entry : m_cacheEntries) {
    //     std::cerr << macToString(entry->mac) << "   "
    //        << ipToString(entry->ip) << "   "
    //        << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
    //        << entry->isValid
    //        << "\n";
    // }
    // #endif

    handleArpRequests();
    removeInvalidEntries();
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
    : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this)) {
}

ArpCache::~ArpCache() {
    m_shouldStop = true;
    m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip) {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& entry : m_cacheEntries) {
        if (entry->isValid && entry->ip == ip) {
            return entry;
        }
    }

    return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest>& request) {
                                    return (request->ip == ip);
                                });

    if (request == m_arpRequests.end()) {
        request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    // Add the packet to the list of packets for this request
    (*request)->packets.push_back({packet, iface});
    return *request;
}

void ArpCache::removeEntry(const uint32_t ip) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::remove_if(m_cacheEntries.begin(), m_cacheEntries.end(),
                   [ip](const std::shared_ptr<ArpEntry>& entry) {
                       return entry->ip == ip;
                   });
}

void ArpCache::removeEntry(const std::shared_ptr<ArpEntry>& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cacheEntries.remove(entry);
}

void ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest>& request) {
                                    return (request->ip == ip);
                                });
    if (request != m_arpRequests.end()) {
        return *request;
    } else {
        return nullptr;
    }
}

void ArpCache::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
}

void ArpCache::ticker() {
    while (!m_shouldStop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto now = steady_clock::now();

            for (auto& entry : m_cacheEntries) {
                if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
                    entry->isValid = false;
                }
            }

            periodicCheckArpRequestsAndCacheEntries();
        }
    }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache) {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto& entry : cache.m_cacheEntries) {
        os << macToString(entry->mac) << "   "
           << ipToString(entry->ip) << "   "
           << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
           << entry->isValid
           << "\n";
    }
    os << std::endl;
    return os;
}

}  // namespace simple_router
