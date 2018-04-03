/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */

#include "net/gnrc.h"

#include "od.h"
#include "checkedc.h"
#include "net/gnrc/icmpv6.h"
#include "net/gnrc/icmpv6/echo.h"
#include "net/gnrc/ipv6/hdr.h"
#include "utlist.h"

#ifdef USE_CHECKEDC
#pragma BOUNDS_CHECKED ON
#endif

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
/* For PRIu16 etc. */
#include <inttypes.h>
#endif

gnrc_pktsnip_t *gnrc_icmpv6_echo_build(uint8_t type, uint16_t id, uint16_t seq,
                                       uint8_t *data acount(data_len), size_t data_len)
    atype(ptr(gnrc_pktsnip_t))
{
    size_t pkt_size = data_len + sizeof(icmpv6_echo_t);
    ptr(gnrc_pktsnip_t) pkt = gnrc_icmpv6_build(NULL, type, 0, pkt_size);

    if (pkt == NULL) {
        return NULL;
    }

    DEBUG("icmpv6_echo: Building echo message with type=%" PRIu8 "id=%" PRIu16
          ", seq=%" PRIu16, type, id, seq);
    array_ptr(icmpv6_echo_t) echo abyte_count(pkt_size) = (array_ptr(icmpv6_echo_t))pkt->data;
    echo->id = byteorder_htons(id);
    echo->seq = byteorder_htons(seq);

    if (data != NULL) {
        memcpy(echo + 1, data, data_len);
#if defined(MODULE_OD) && ENABLE_DEBUG
        DEBUG(", payload:\n");
        od_hex_dump(data, data_len, OD_WIDTH_DEFAULT);
#endif
    }
    DEBUG("\n");

    return pkt;
}

void gnrc_icmpv6_echo_req_handle(gnrc_netif_t *netif atype(ptr(gnrc_netif_t)),
                                 ipv6_hdr_t *ipv6_hdr atype(ptr(ipv6_hdr_t)),
                                 icmpv6_echo_t *echo abyte_count(len + sizeof(icmpv6_echo_t)),
                                 uint16_t len)
{
    array_ptr(uint8_t) payload acount(len) = ((array_ptr(uint8_t))echo) + sizeof(icmpv6_echo_t);

    if ((echo == NULL) || (len < sizeof(icmpv6_echo_t))) {
        DEBUG("icmpv6_echo: echo was NULL or len (%" PRIu16
              ") was < sizeof(icmpv6_echo_t)\n", len);
        return;
    }

    ptr(gnrc_pktsnip_t) pkt = gnrc_icmpv6_echo_build(ICMPV6_ECHO_REP, byteorder_ntohs(echo->id),
                                                     byteorder_ntohs(echo->seq), payload,
                                                     len - sizeof(icmpv6_echo_t));

    if (pkt == NULL) {
        DEBUG("icmpv6_echo: no space left in packet buffer\n");
        return;
    }

    ptr(gnrc_pktsnip_t) hdr = NULL;
    if (ipv6_addr_is_multicast(&ipv6_hdr->dst)) {
        hdr = gnrc_ipv6_hdr_build(pkt, NULL, &ipv6_hdr->src);
    }
    else {
        hdr = gnrc_ipv6_hdr_build(pkt, &ipv6_hdr->dst, &ipv6_hdr->src);
    }

    if (hdr == NULL) {
        DEBUG("icmpv6_echo: no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    pkt = hdr;
    hdr = gnrc_netif_hdr_build(NULL, 0, NULL, 0);

    if (netif != NULL) {
        ((ptr(gnrc_netif_hdr_t))hdr->data)->if_pid = netif->pid;
    }
    else {
        /* ipv6_hdr->dst is loopback address */
        ((ptr(gnrc_netif_hdr_t))hdr->data)->if_pid = KERNEL_PID_UNDEF;
    }

    LL_PREPEND(pkt, hdr);

    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6, GNRC_NETREG_DEMUX_CTX_ALL,
                                   pkt)) {
        DEBUG("icmpv6_echo: no receivers for IPv6 packets\n");
        gnrc_pktbuf_release(pkt);
    }
}

/** @} */
