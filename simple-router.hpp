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

#ifndef SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
#define SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

#include "arp-cache.hpp"
#include "core/interface.hpp"
#include "core/protocol.hpp"
#include "pox.hpp"
#include "routing-table.hpp"

namespace simple_router {

class SimpleRouter {
   public:
    SimpleRouter();

    /**
   * IMPLEMENT THIS METHOD
   *
   * This method is called each time the router receives a packet on
   * the interface.  The packet buffer \p packet and the receiving
   * interface \p inIface are passed in as parameters. The packet is
   * complete with ethernet headers.
   */
    /******************************************************************************
    * Packet Handling
    ******************************************************************************/
    void handlePacket(const Buffer& packet, const std::string& inIface);
    void handleIPv4Packet(const Buffer& packet, const std::string& inIface);
    void handleIcmpPacket(const Buffer* packet, const std::string& inIface);
    void handleArpPacket(const Buffer& packet, const std::string& inIface);
    void handleArpReply(const Buffer& packet);

    /**
   * USE THIS METHOD TO SEND PACKETS
   *
   * Call this method to send packet \p packt from the router on interface \p outIface
   */
    void sendPacket(const Buffer& packet, const std::string& outIface);

    /**
   * Load routing table information from \p rtConfig file
   */
    bool
    loadRoutingTable(const std::string& rtConfig);

    /**
   * Load local interface configuration
   */
    void
    loadIfconfig(const std::string& ifconfig);

    /**
   * Get routing table
   */
    const RoutingTable&
    getRoutingTable() const;

    /**
   * Get ARP table
   */
    const ArpCache&
    getArp() const;

    /**
   * Print router interfaces
   */
    void
    printIfaces(std::ostream& os);

    /**
   * Reset ARP cache and interface list (e.g., when mininet restarted)
   */
    void
    reset(const pox::Ifaces& ports);

    /**
   * Find interface based on interface's IP address
   */
    const Interface*
    findIfaceByIp(uint32_t ip) const;

    /**
   * Find interface based on interface's MAC address
   */
    const Interface*
    findIfaceByMac(const Buffer& mac) const;

    /**
   * Find interface based on interface's name
   */
    const Interface*
    findIfaceByName(const std::string& name) const;

    /******************************************************************************
    * Validity check
    ******************************************************************************/
    bool checkEther(const Buffer& packet, const std::string& IfaceName);
    bool checkArp(const Buffer& packet);
    bool checkIPv4(const Buffer& packet);
    bool checkICMP(const Buffer& packet);

    /******************************************************************************
    * ARP
    ******************************************************************************/
    void sendArpRequest(uint32_t ip);
    void replyArpReply(const Buffer& packet, const std::string& inIface);

    /******************************************************************************
    * IPv4
    ******************************************************************************/
    void dispatchIPv4Packet(const Buffer& packet, const std::string& inIface);

    /******************************************************************************
    * ICMP
    ******************************************************************************/
    void replyICMP(const Buffer& packet, uint8_t icmp_type, uint8_t icmp_code);
    void replyIcmpEchoReply(const Buffer& packet);
    void replyIcmpNetUnreachable(const Buffer& packet);
    void replyIcmpHostUnreachable(const Buffer& packet);
    void replyIcmpPortUnreachable(const Buffer& packet);
    void replyIcmpTimeExceeded(const Buffer& packet);

   private:
    ArpCache m_arp;
    RoutingTable m_routingTable;
    std::set<Interface> m_ifaces;
    std::map<std::string, uint32_t> m_ifNameToIpMap;

    friend class Router;
    pox::PacketInjectorPrx m_pox;
};

inline const RoutingTable&
SimpleRouter::getRoutingTable() const {
    return m_routingTable;
}

inline const ArpCache&
SimpleRouter::getArp() const {
    return m_arp;
}

}  // namespace simple_router

#endif  // SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
