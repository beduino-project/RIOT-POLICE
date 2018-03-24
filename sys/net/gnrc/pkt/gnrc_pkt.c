/*
 * Copyright (C) 2016 Freie Universität Berlin
 *               2017 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 * @author  Sebastian Meiling <s@mlng.net>
 */

#include "checkedc.h"
#include "net/gnrc/pkt.h"

#ifdef USE_CHECKEDC
#pragma BOUNDS_CHECKED ON
#endif

gnrc_pktsnip_t *gnrc_pktsnip_search_type(gnrc_pktsnip_t *pkt atype(ptr(gnrc_pktsnip_t)),
                                         gnrc_nettype_t type)
        atype(ptr(gnrc_pktsnip_t))
{
    while ((pkt != NULL) && (pkt->type != type)) {
        pkt = pkt->next;
    }
    return pkt;
}

/** @} */
