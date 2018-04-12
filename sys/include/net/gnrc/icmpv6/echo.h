/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gnrc_icmpv6_echo  ICMPv6 echo messages
 * @ingroup     net_gnrc_icmpv6
 * @brief       ICMPv6 echo request and reply
 * @{
 *
 * @file
 * @brief   ICMPv6 echo message definitions
 *
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 */
#ifndef NET_GNRC_ICMPV6_ECHO_H
#define NET_GNRC_ICMPV6_ECHO_H

#include <inttypes.h>

#include "checkedc.h"
#include "byteorder.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/hdr.h"

#ifdef USE_CHECKEDC
#pragma BOUNDS_CHECKED ON
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Builds an ICMPv6 echo message of type @p type for sending.
 *
 * @param[in] type      Type of the echo message. Expected to be either
 *                      ICMPV6_ECHO_REQ or ICMPV6_ECHO_REP.
 * @param[in] id        ID for the echo message in host byte-order
 * @param[in] seq       Sequence number for the echo message in host byte-order
 * @param[in] data      Payload for the echo message
 * @param[in] data_len  Length of @p data
 *
 * @return  The echo message on success
 * @return  NULL, on failure
 */
gnrc_pktsnip_t *gnrc_icmpv6_echo_build(uint8_t type, uint16_t id, uint16_t seq,
                                       uint8_t *data acount(data_len), size_t data_len)
    atype(ptr(gnrc_pktsnip_t));

/**
 * @brief   ICMPv6 echo request handler
 *
 * @param[in] netif     The interface the echo request was received on.
 * @param[in] ipv6_hdr  The IPv6 header of the echo request.
 * @param[in] echo      The Echo Request message.
 * @param[in] len       Length of the echo request message (ipv6_hdr_t::len
 *                      of @p ipv6_hdr minus length of extension headers).
 */
void gnrc_icmpv6_echo_req_handle(gnrc_netif_t *netif atype(ptr(gnrc_netif_t)),
                                 ipv6_hdr_t *ipv6_hdr atype(ptr(ipv6_hdr_t)),
                                 icmpv6_echo_t *echo abyte_count(len + sizeof(icmpv6_echo_t)),
                                 uint16_t len);

#ifdef __cplusplus
}
#endif

#ifdef USE_CHECKEDC
#pragma BOUNDS_CHECKED OFF
#endif

#endif /* NET_GNRC_ICMPV6_ECHO_H */
/** @} */
