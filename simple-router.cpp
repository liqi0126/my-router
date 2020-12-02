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

    print_hdrs(packet);

    // FILL THIS IN
    if (!checkEther(packet, inIface)) {
        CERR("Ether Header check failed...");
        return;
    }

    struct ethernet_hdr* hEther = (struct ethernet_hdr*)packet.data();
    if (ethertype(hEther) == ethertype_arp) {
        CERR("Handling ARP Packet...");
        handleArpPacket(packet, inIface);
    } else if (ethertype(hEther) == ethertype_ip) {
        CERR("Handling IPv4 Packet...");
        handleIPv4Packet(packet, inIface);
    }
}

void SimpleRouter::handleArpPacket(const Buffer& packet, const std::string& inIface) {
    if (!checkArp(packet)) {
        CERR("Arp Header check failed...");
        return;
    }

    struct arp_hdr* hARP = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    const Interface* iface = findIfaceByName(inIface);

    // ignore ARP if the target ip is not router's IP
    if (hARP->arp_tip != iface->ip) {
        CERR("ARP IP is not the IP of interface, ignore it.");
        return;
    }

    if (ntohs(hARP->arp_op) == ARP_OP_REQUEST) {
        CERR("Handling ARP Request...");
        replyArpReply(packet, inIface);
    } else if (ntohs(hARP->arp_op) == ARP_OP_REPLY) {
        CERR("Handling ARP Reply...");
        handleArpReply(packet);
    }
}

void SimpleRouter::handleArpReply(const Buffer& packet) {
    struct arp_hdr* hARP = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    uint32_t IP = hARP->arp_sip;
    Buffer MAC(hARP->arp_sha, hARP->arp_sha + ETHER_ADDR_LEN);
    // clean old entries firstly.
    CERR("Cleaning old Entry...");
    m_arp.removeEntry(IP);

    // handle queued requests
    CERR("Add new Entry.");
    auto request = m_arp.insertArpEntry(MAC, IP);
    if (request != nullptr) {
        CERR("Handling queued package.");
        for (auto pendingPacket : request->packets) {
            handlePacket(pendingPacket.packet, pendingPacket.iface);
        }
        m_arp.removeRequest(request);
    }
}

void SimpleRouter::handleIPv4Packet(const Buffer& packet, const std::string& inIface) {
    if (!checkIPv4(packet)) {
        CERR("IPv4 header check failed...");
        return;
    }

    struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    if (findIfaceByIp(hIPv4->ip_dst) != nullptr) {  // destined to the router
        CERR("IPv4 package target to router.");
        if (hIPv4->ip_p == ip_protocol_icmp) {
            if (!checkICMP(packet)) {
                CERR("ICMP header check failed...");
                return;
            }

            struct icmp_hdr* hICMP = (struct icmp_hdr*)((uint8_t*)hIPv4 + sizeof(struct ip_hdr));
            if (hICMP->icmp_type == ICMP_TYPE_ECHO && hICMP->icmp_code == ICMP_CODE_ECHO) {
                CERR("reply ICMP ECHO REPLY...");
                replyIcmpEchoReply(packet);
            }
        } else if (hIPv4->ip_p == ip_protocol_tcp || hIPv4->ip_p == ip_protocol_udp) {
            CERR("router cann't handle TCP or UDP, reply ICMP PORT UNREACHABLE...");
            replyIcmpPortUnreachable(packet);
        }
    } else {  // datagrams to be forwarded
        CERR("Dispatch IPv4 Packet.");
        dispatchIPv4Packet(packet, inIface);
    }
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
        CERR("Interface not found");
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
        CERR("Interface not found");
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
        CERR("Interface not found");
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

/******************************************************************************
* Validity check
******************************************************************************/

bool SimpleRouter::checkEther(const Buffer& packet, const std::string& IfaceName) {
    if (packet.size() < sizeof(struct ethernet_hdr)) {
        return false;
    }

    struct ethernet_hdr* hEther = (struct ethernet_hdr*)packet.data();
    uint16_t type = ethertype(hEther);
    if (type != ethertype_arp && type != ethertype_ip) {
        return false;
    }

    const auto Iface = findIfaceByName(IfaceName);
    // corresponding MAC address of the interface
    if (memcmp(hEther->ether_dhost, Iface->addr.data(), ETHER_ADDR_LEN) == 0) {
        return true;
    }
    // broadcast
    if (is_broadcast(hEther->ether_dhost)) {
        return true;
    }

    return false;
}

bool SimpleRouter::checkArp(const Buffer& packet) {
    if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
        return false;
    }

    struct arp_hdr* hARP = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    if (ntohs(hARP->arp_hrd) != arp_hrd_ethernet) {
        return false;
    }

    if (ntohs(hARP->arp_pro) != 0x800) {
        return false;
    }

    if (ntohs(hARP->arp_op) != 1 && ntohs(hARP->arp_op) != 2) {
        return false;
    }

    if (hARP->arp_hln != 0x06) {
        return false;
    }

    if (hARP->arp_pln != 0x04) {
        return false;
    }

    return true;
}

bool SimpleRouter::checkIPv4(const Buffer& packet) {
    if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
        return false;
    }

    struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    uint16_t checksum = hIPv4->ip_sum;
    hIPv4->ip_sum = 0;
    if (cksum(hIPv4, sizeof(struct ip_hdr)) != checksum) {
        hIPv4->ip_sum = checksum;
        return false;
    } else {
        hIPv4->ip_sum = checksum;
        return true;
    }
}

bool SimpleRouter::checkICMP(const Buffer& packet) {
    if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)) {
        return false;
    }
    struct icmp_hdr* hICMP = (struct icmp_hdr*)(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));

    uint16_t checksum = cksum(hICMP, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
    if (checksum != 0xffff) {
        return false;
    }
    return true;
}

/******************************************************************************
* ARP
******************************************************************************/

void SimpleRouter::sendArpRequest(uint32_t ip) {
    Buffer request(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)(request.data());
    struct arp_hdr* hArp = (struct arp_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));

    // get Interface
    const auto routingEntry = m_routingTable.lookup(ip);
    const auto outIface = findIfaceByName(routingEntry.ifName);

    // build Ethernet header
    memcpy(hEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memset(hEther->ether_dhost, 0xff, ETHER_ADDR_LEN);  // broadcast
    hEther->ether_type = htons(ethertype_arp);

    // build Arp header
    hArp->arp_hrd = htons(ARP_HRD_ETHER);
    hArp->arp_pro = htons(APR_PRO_IPV4);
    hArp->arp_hln = ARP_HW_LEN;
    hArp->arp_pln = ARP_PORT_LEN;
    hArp->arp_op = htons(ARP_OP_REQUEST);
    memcpy(hArp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
    hArp->arp_sip = outIface->ip;
    memset(hArp->arp_tha, 0xff, ETHER_ADDR_LEN);
    hArp->arp_tip = ip;

    sendPacket(request, outIface->name);
}

void SimpleRouter::replyArpReply(const Buffer& packet, const std::string& inIface) {
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)packet.data();
    struct arp_hdr* hARP = (struct arp_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));

    // copy the old packet
    Buffer reply(packet);
    struct ethernet_hdr* hReplyEther = (struct ethernet_hdr*)reply.data();
    struct arp_hdr* hReplyARP = (struct arp_hdr*)((uint8_t*)hReplyEther + sizeof(struct ethernet_hdr));

    // get Mac address
    const Interface* inface = findIfaceByName(inIface);

    // swap Ether dst and src
    memcpy(hReplyEther->ether_dhost, hEther->ether_shost, ETHER_ADDR_LEN);
    memcpy(hReplyEther->ether_shost, inface->addr.data(), ETHER_ADDR_LEN);

    // swap ARP dst and src
    memcpy(hReplyARP->arp_tha, hARP->arp_sha, ETHER_ADDR_LEN);
    memcpy(hReplyARP->arp_sha, inface->addr.data(), ETHER_ADDR_LEN);
    hReplyARP->arp_tip = hARP->arp_sip;
    hReplyARP->arp_sip = hARP->arp_tip;
    hReplyARP->arp_op = htons(ARP_OP_REPLY);

    sendPacket(reply, inface->name);
}

/******************************************************************************
* IPv4
******************************************************************************/

void SimpleRouter::dispatchIPv4Packet(const Buffer& packet, const std::string& inIface) {
    struct ip_hdr* hIPv4 = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));

    if (hIPv4->ip_ttl - 1 <= 0) {
        CERR("TTL = 0, reply ICMP TIME EXCEEDED.");
        replyIcmpTimeExceeded(packet);
        return;
    }

    CERR("ping1");
    RoutingTableEntry routingEntry;
    try {
        routingEntry = m_routingTable.lookup(hIPv4->ip_dst);
    } catch (const std::runtime_error& error) {
        CERR("Routing Table has no entry for target IP, return ICMP NET UNREACHABLE.");
        replyIcmpNetUnreachable(packet);
        return;
    }

    CERR("ping2");
    auto arpEntry = m_arp.lookup(routingEntry.gw);
    if (arpEntry == nullptr) {  // don't have a arp entry yet
        // queue request
        CERR("Don't have a ARP Entry yet, queue it.");
        m_arp.queueRequest(hIPv4->ip_dst, packet, inIface);
        return;
    }
    CERR("Find ARP Entry, dispatch it.");

    // make a copy
    CERR("ping3");
    Buffer dispatch = packet;
    struct ethernet_hdr* hDispatchEther = (struct ethernet_hdr*)dispatch.data();
    struct ip_hdr* hDispatchIPv4 = (struct ip_hdr*)((uint8_t*)hDispatchEther + sizeof(struct ethernet_hdr));
    const auto outIface = findIfaceByName(routingEntry.ifName);
    // prepare ethernet header
    memcpy(hDispatchEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memcpy(hDispatchEther->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
    // prepare ip header
    hDispatchIPv4->ip_ttl -= 1;
    hDispatchIPv4->ip_sum = 0;
    hDispatchIPv4->ip_sum = cksum(hDispatchIPv4, sizeof(struct ip_hdr));
    sendPacket(dispatch, outIface->name);
}

/******************************************************************************
* ICMP
******************************************************************************/

void SimpleRouter::replyICMP(const Buffer& packet, uint8_t icmp_type, uint8_t icmp_code) {
    struct ethernet_hdr* hEther = (struct ethernet_hdr*)(packet.data());
    struct ip_hdr* hIPv4 = (struct ip_hdr*)((uint8_t*)hEther + sizeof(struct ethernet_hdr));

    // Buffer reply(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
    Buffer reply(packet);
    struct ethernet_hdr* hReplyEther = (struct ethernet_hdr*)reply.data();
    struct ip_hdr* hReplyIPv4 = (struct ip_hdr*)((uint8_t*)hReplyEther + sizeof(struct ethernet_hdr));
    struct icmp_t3_hdr* hReplyICMPT3 = (struct icmp_t3_hdr*)((uint8_t*)hReplyIPv4 + sizeof(struct ip_hdr));

    // get Interface
    const auto routingEntry = m_routingTable.lookup(hIPv4->ip_src);  // reply to src ip
    const auto outIface = findIfaceByName(routingEntry.ifName);

    // build Ethernet header
    memcpy(hReplyEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    memcpy(hReplyEther->ether_dhost, hEther->ether_shost, ETHER_ADDR_LEN);  // send back
    hReplyEther->ether_type = htons(ethertype_ip);

    // build IP
    // hReplyIPv4->ip_tos = 0;  
    hReplyIPv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
    // hReplyIPv4->ip_id = 0;
    // hReplyIPv4->ip_off = 0;  
    hReplyIPv4->ip_ttl = IP_TLL;
    hReplyIPv4->ip_p = ip_protocol_icmp;
    hReplyIPv4->ip_sum = 0;
    hReplyIPv4->ip_src = outIface->ip;
    hReplyIPv4->ip_dst = hIPv4->ip_src;
    hReplyIPv4->ip_sum = cksum(hReplyIPv4, sizeof(struct ip_hdr));

    // build ICMP T3
    hReplyICMPT3->icmp_type = icmp_type;
    hReplyICMPT3->icmp_code = icmp_code;
    hReplyICMPT3->icmp_sum = 0;
    // hReplyICMPT3->unused = 0;
    // hReplyICMPT3->next_mtu = 0;
    memcpy(hReplyICMPT3->data, hIPv4, ICMP_DATA_SIZE);
    hReplyICMPT3->icmp_sum = cksum(hReplyICMPT3, sizeof(struct icmp_t3_hdr));

    #ifdef DEBUG
    CERR("ICMP package:");
    print_hdrs(reply);
    #endif

    sendPacket(reply, outIface->name);
}

void SimpleRouter::replyIcmpEchoReply(const Buffer& packet) {
    replyICMP(packet, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO_REPLY);
}

void SimpleRouter::replyIcmpNetUnreachable(const Buffer& packet) {
    replyICMP(packet, ICMP_TYPE_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE);
}

void SimpleRouter::replyIcmpHostUnreachable(const Buffer& packet) {
    replyICMP(packet, ICMP_TYPE_UNREACHABLE, ICMP_CODE_HOST_UNREACHABLE);
}

void SimpleRouter::replyIcmpPortUnreachable(const Buffer& packet) {
    replyICMP(packet, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE);
}

void SimpleRouter::replyIcmpTimeExceeded(const Buffer& packet) {
    replyICMP(packet, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED);
}

}  // namespace simple_router
