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

#include "simple-router.hpp"

#include <fstream>

#include "core/utils.hpp"

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface) {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
    : m_arp(*this) {
}

void SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface) {
    m_pox->begin_sendPacket(packet, outIface);
}

bool SimpleRouter::loadRoutingTable(const std::string& rtConfig) {
    return m_routingTable.load(rtConfig);
}

void SimpleRouter::loadIfconfig(const std::string& ifconfig) {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line)) {
        std::istringstream ifLine(line);
        std::string iface, ip;
        ifLine >> iface >> ip;

        in_addr ip_addr;
        if (inet_aton(ip.c_str(), &ip_addr) == 0) {
            throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
        }

        m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
}

void SimpleRouter::printIfaces(std::ostream& os) {
    if (m_ifaces.empty()) {
        os << " Interface list empty " << std::endl;
        return;
    }

    for (const auto& iface : m_ifaces) {
        os << iface << "\n";
    }
    os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface& iface) {
        return iface.ip == ip;
    });

    if (iface == m_ifaces.end()) {
        return nullptr;
    }

    return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface& iface) {
        return iface.addr == mac;
    });

    if (iface == m_ifaces.end()) {
        return nullptr;
    }

    return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface& iface) {
        return iface.name == name;
    });

    if (iface == m_ifaces.end()) {
        return nullptr;
    }

    return &*iface;
}

void SimpleRouter::reset(const pox::Ifaces& ports) {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto& iface : ports) {
        auto ip = m_ifNameToIpMap.find(iface.name);
        if (ip == m_ifNameToIpMap.end()) {
            std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
            continue;
        }

        m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
}

void SimpleRouter::sendArpRequest(uint32_t ip) {
    Buffer request(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)(request.data());
    struct arp_hdr* hArp = (struct arp_hdr*)((unit8_t*)pEther + sizeof(struct ethernet_hdr));

    // get Interface
    const auto routingEntry = m_routingTable.lookup(ip);
    const auto outIface = findIfaceByName(routingEntry.ifName);

    // build Ethernet header
    memset(hEther->ether_dhost, 0xff, ETHER_ADDR_LEN);  // broadcast
    memcpy(hEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    hEther.ether_type = htons(ethertype_arp);

    // build Arp header
    hArp->arp_hrd = htons(0x0001);
    hArp->arp_pro = htons(0x0800);
    hArp->arp_hln = 0x06;
    hArp->arp_pln = 0x04;
    hArp->arp_op = htons(0x0001);
    memcpy(hArp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
    hArp->arp_sip = outIface->ip;
    memset(hArp->arp_tha, 0xff, ETHER_ADDR_LEN);
    hArp->arp_tip = ip;

    sendPacket(request, outIface->name);
}

void SimpleRouter::replyIcmpHostUnreachable(Buffer& packet) {
    struct
}

}  // namespace simple_router
