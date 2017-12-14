/*
 * Copyright (C) 2016-17 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_net_nanocoap
 * @{
 *
 * @file
 * @brief       Nanocoap implementation
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 *
 * @}
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "checkedc.h"
#include "net/nanocoap.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#ifdef USE_CHECKEDC
#include "string_checked.h"
#pragma BOUNDS_CHECKED ON
#endif

static ptr(uint8_t) _decode_value(ptr(int) res, unsigned val,
                              array_ptr(uint8_t) pkt_start abounds(pkt_start, pkt_end),
                              array_ptr(uint8_t) pkt_end);
static uint32_t _decode_uint(array_ptr(uint8_t) pkt_pos abounds(pkt_pos, pkt_end),
                             array_ptr(uint8_t) pkt_end, unsigned nbytes);


/* http://tools.ietf.org/html/rfc7252#section-3
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver| T |  TKL  |      Code     |          Message ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Token (if any, TKL bytes) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Options (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1 1 1 1 1|    Payload (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int coap_parse(coap_pkt_t *pkt atype(ptr(coap_pkt_t)),
               uint8_t *buf acount(len), size_t len)
{
    int option_delta, option_len;
    array_ptr(uint8_t) urlpos abounds(pkt->url, pkt->url + NANOCOAP_URL_MAX) = pkt->url;
    ptr(coap_hdr_t) hdr = dynamic_cast(ptr(coap_hdr_t), buf);

    pkt->hdr = hdr;

    array_ptr(uint8_t) pkt_end = buf + len;
    array_ptr(uint8_t) pkt_pos abounds(buf + sizeof(coap_hdr_t), pkt_end)
        = buf + sizeof(coap_hdr_t);

    memset(pkt->url, '\0', NANOCOAP_URL_MAX);
    pkt->payload_len = 0;
    pkt->observe_value = UINT32_MAX;

    /* token value (tkl bytes) */
    if (coap_get_token_len(pkt)) {
        pkt->token = pkt_pos;
        pkt_pos += coap_get_token_len(pkt);
    }
    else {
        pkt->token = NULL;
    }

    /* parse options */
    int option_nr = 0;
    while (pkt_pos != pkt_end) {
        uint8_t option_byte = *pkt_pos++;
        if (option_byte == 0xff) {
            pkt->payload = pkt_pos;
            pkt->payload_len = pkt_end - pkt_pos;
            DEBUG("payload len = %u\n", pkt->payload_len);
            break;
        }
        else {
            pkt_pos = _decode_value(&option_delta, option_byte >> 4, pkt_pos, pkt_end);
            if (!pkt_pos) {
                DEBUG("bad op delta\n");
                return -EBADMSG;
            }
            pkt_pos = _decode_value(&option_len, option_byte & 0xf, pkt_pos, pkt_end);
            if (!pkt_pos) {
                DEBUG("bad op len\n");
                return -EBADMSG;
            }
            option_nr += option_delta;
            DEBUG("option nr=%i len=%i\n", option_nr, option_len);

            switch (option_nr) {
                case COAP_OPT_URI_HOST:
                    DEBUG("nanocoap: ignoring Uri-Host option!\n");
                    break;
                case COAP_OPT_URI_PATH:
                    *urlpos++ = '/';
                    memcpy(urlpos, pkt_pos, option_len);
                    urlpos += option_len;
                    break;
                case COAP_OPT_CONTENT_FORMAT:
                    if (option_len == 0) {
                        pkt->content_type = 0;
                    }
                    else if (option_len == 1) {
                        pkt->content_type = *pkt_pos;
                    }
                    else if (option_len == 2) {
                        memcpy(&pkt->content_type, pkt_pos, 2);
                        pkt->content_type = ntohs(pkt->content_type);
                    }
                    break;
                case COAP_OPT_OBSERVE:
                    if (option_len < 4) {
                        pkt->observe_value = _decode_uint(pkt_pos, pkt_end, option_len);
                    }
                    else {
                        DEBUG("nanocoap: discarding packet with invalid option length.\n");
                        return -EBADMSG;
                    }
                    break;
                default:
                    DEBUG("nanocoap: unhandled option nr=%i len=%i critical=%u\n", option_nr, option_len, option_nr & 1);
                    if (option_nr & 1) {
                        DEBUG("nanocoap: discarding packet with unknown critical option.\n");
                        return -EBADMSG;
                    }
            }

            pkt_pos += option_len;
        }
    }

    DEBUG("coap pkt parsed. code=%u detail=%u payload_len=%u, 0x%02x\n",
          coap_get_code_class(pkt),
          coap_get_code_detail(pkt),
          pkt->payload_len, hdr->code);

    return 0;
}

ssize_t coap_handle_req(coap_pkt_t *pkt atype(ptr(coap_pkt_t)),
                        uint8_t *resp_buf acount(resp_buf_len),
                        unsigned resp_buf_len)
{
    if (coap_get_code_class(pkt) != COAP_REQ) {
        DEBUG("coap_handle_req(): not a request.\n");
        return -EBADMSG;
    }

    if (pkt->hdr->code == 0) {
        return coap_build_reply(pkt, COAP_CODE_EMPTY, resp_buf, resp_buf_len, 0);
    }

    unsigned method_flag = coap_method2flag(coap_get_code_detail(pkt));

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (!(coap_resources[i].methods & method_flag)) {
            continue;
        }

        int res = strcmp((nt_array_ptr(char))pkt->url, coap_resources[i].path);
        if (res > 0) {
            continue;
        }
        else if (res < 0) {
            break;
        }
        else {
            return coap_resources[i].handler(pkt, resp_buf, resp_buf_len);
        }
    }

    return coap_build_reply(pkt, COAP_CODE_404, resp_buf, resp_buf_len, 0);
}

ssize_t coap_reply_simple(coap_pkt_t *pkt atype(ptr(coap_pkt_t)),
                          unsigned code,
                          uint8_t *buf acount(len),
                          size_t len,
                          unsigned ct,
                          const uint8_t *payload acount(payload_len),
                          uint8_t payload_len)
{
    array_ptr(uint8_t) payload_end = buf + len;
    array_ptr(uint8_t) payload_start abounds(buf, buf + len)
        = buf + coap_get_total_hdr_len(pkt);
    array_ptr(uint8_t) bufpos abounds(payload_start, payload_end)
        = payload_start;

    if (payload_len) {
        bufpos += coap_put_option_ct(bufpos, payload_end, 0, ct);
        *bufpos++ = 0xff;

        memcpy(bufpos, payload, payload_len);
        bufpos += payload_len;
    }

    return coap_build_reply(pkt, code, buf, len, bufpos - payload_start);
}

ssize_t coap_build_reply(coap_pkt_t *pkt atype(ptr(coap_pkt_t)), unsigned code,
                         uint8_t *rbuf acount(rlen), unsigned rlen,
                         unsigned payload_len)
{
    unsigned tkl = coap_get_token_len(pkt);
    unsigned len = sizeof(coap_hdr_t) + tkl;

    if ((len + payload_len + 1) > rlen) {
        return -ENOSPC;
    }

    /* if code is COAP_CODE_EMPTY (zero), use RST as type, else RESP */
    unsigned type = code ? COAP_RESP : COAP_RST;

    coap_build_hdr((ptr(coap_hdr_t))rbuf, type, pkt->token, tkl,
                   rbuf, rlen, code, ntohs(pkt->hdr->id));
    coap_hdr_set_type((ptr(coap_hdr_t))rbuf, type);
    coap_hdr_set_code((ptr(coap_hdr_t))rbuf, code);

    len += payload_len;

    return len;
}

ssize_t coap_build_hdr(coap_hdr_t *hdr atype(ptr(coap_hdr_t)), unsigned type,
                       uint8_t *token acount(token_len), size_t token_len,
                       uint8_t *buf acount(buf_len), size_t buf_len,
                       unsigned code, uint16_t id)
{
    assert(!(type & ~0x3));
    assert(!(token_len & ~0x1f));

    memset(hdr, 0, sizeof(coap_hdr_t));
    hdr->ver_t_tkl = (0x1 << 6) | (type << 4) | token_len;
    hdr->code = code;
    hdr->id = htons(id);

    if (token_len && buf_len >= token_len + sizeof(coap_hdr_t)) {
        memcpy(buf + sizeof(coap_hdr_t), token, token_len);
    }

    return sizeof(coap_hdr_t) + token_len;
}

static ptr(uint8_t) _decode_value(ptr(int) res, unsigned val,
                              array_ptr(uint8_t) pkt_start abounds(pkt_start, pkt_end),
                              array_ptr(uint8_t) pkt_end)
{
    array_ptr(uint8_t) pkt_pos abounds(pkt_start, pkt_end) = pkt_start;
    size_t left = pkt_end - pkt_pos;

    switch (val) {
        case 13:
        {
            /* An 8-bit unsigned integer follows the initial byte and
               indicates the Option Delta minus 13. */
            if (left < 1) {
                return NULL;
            }
            uint8_t delta = *pkt_pos++;
            *res = delta + 13;
            break;
        }
        case 14:
        {
            /* A 16-bit unsigned integer in network byte order follows
             * the initial byte and indicates the Option Delta minus
             * 269. */
            if (left < 2) {
                return NULL;
            }
            uint16_t delta;
            array_ptr(uint8_t) _tmp abounds(&delta, &delta + 1) = (array_ptr(uint8_t))&delta;
            *_tmp++ = *pkt_pos++;
            *_tmp++ = *pkt_pos++;
            *res = ntohs(delta) + 269;
            break;
        }
        case 15:
            /* Reserved for the Payload Marker.  If the field is set to
             * this value but the entire byte is not the payload
             * marker, this MUST be processed as a message format
             * error. */
            return NULL;
        default:
            *res = val;
    }

    return dynamic_cast(ptr(uint8_t), pkt_pos);
}

static uint32_t _decode_uint(array_ptr(uint8_t) pkt_pos abounds(pkt_pos, pkt_end),
                             array_ptr(uint8_t) pkt_end, unsigned nbytes)
{
#ifdef NDEBUG
    (void)pkt_end;
#endif
    assert(nbytes <= 3);
    assert(pkt_pos + nbytes < pkt_end);

    uint32_t res = 0;
    if (nbytes >= 1)
        res = pkt_pos[0];
    if (nbytes >= 2)
        res = pkt_pos[1] + res;
    if (nbytes >= 3)
        res = pkt_pos[2] + res;

    return ntohl(res);
}

static unsigned _put_delta_optlen(array_ptr(uint8_t) buf abounds(buf, end),
                                  array_ptr(uint8_t) end, unsigned offset,
                                  unsigned shift, unsigned val)
{
    size_t left = end - buf;
    if (offset + sizeof(uint16_t) > left) {
        return 0;
    }

    if (val < 13) {
        *buf |= (val << shift);
    }
    else if (val < (256 + 13)) {
        *buf |= (13 << shift);
        buf[offset++] = (val - 13);
    }
    else {
        *buf |= (14 << shift);
        uint16_t tmp = (val - 269);
        tmp = htons(tmp);
        memcpy(buf + offset, &tmp, 2);
        offset += 2;
    }
    return offset;
}

unchecked /* https://github.com/Microsoft/checkedc-clang/issues/443 */
size_t coap_put_option(uint8_t *buf abounds(buf, bend),
                       uint8_t *bend atype(array_ptr(uint8_t)),
                       uint16_t lastonum, uint16_t onum,
                       uint8_t *odata acount(olen), size_t olen)
checked {
    size_t left = bend - buf;
    assert(lastonum <= onum);

    unsigned delta = (onum - lastonum);
    *buf = 0;

    /* write delta value to option header: 4 upper bits of header (shift 4) +
     * 1 or 2 optional bytes depending on delta value) */
    unsigned n = _put_delta_optlen(buf, bend, 1, 4, delta);
    if (!n) {
        return 0;
    }

    /* write option length to option header: 4 lower bits of header (shift 0) +
     * 1 or 2 optional bytes depending of the length of the option */
    n = _put_delta_optlen(buf, bend, n, 0, olen);
    if (olen && n && n + olen <= left) {
        memcpy(buf + n, odata, olen);
        n += olen;
    }
    return (size_t)n;
}

unchecked /* https://github.com/Microsoft/checkedc-clang/issues/443 */
size_t coap_put_option_ct(uint8_t *buf abounds(buf, end),
                          uint8_t *end atype(array_ptr(uint8_t)),
                          uint16_t lastonum, uint16_t content_type)
checked {
    if (content_type == 0) {
        return coap_put_option(buf, end, lastonum, COAP_OPT_CONTENT_FORMAT, NULL, 0);
    }
    else if (content_type <= 255) {
        uint8_t tmp = content_type;
        return coap_put_option(buf, end, lastonum, COAP_OPT_CONTENT_FORMAT, &tmp, sizeof(tmp));
    }
    else {
        return coap_put_option(buf, end, lastonum, COAP_OPT_CONTENT_FORMAT,
                               (array_ptr(uint8_t))&content_type, sizeof(content_type));
    }
}

unchecked /* https://github.com/Microsoft/checkedc-clang/issues/443 */
size_t coap_put_option_uri(uint8_t *buf abounds(buf, end),
                           uint8_t *end atype(array_ptr(uint8_t)),
                           uint16_t lastonum,
                           const char *uri atype(nt_array_ptr(const char)),
                           uint16_t optnum)
checked {
    char separator = (optnum == COAP_OPT_URI_PATH) ? '/' : '&';
    size_t uri_len = strlen(uri);

    if (uri_len == 0) {
        return 0;
    }

    array_ptr(uint8_t) bufpos abounds(buf, end) = buf;
    nt_array_ptr(char) uripos = (nt_array_ptr(char))uri;

    while (uri_len) {
        size_t part_len;
        uripos++;
        nt_array_ptr(uint8_t) part_start = (nt_array_ptr(uint8_t))uripos;

        while (uri_len--) {
            if ((*uripos == separator) || (*uripos == '\0')) {
                break;
            }
            uripos++;
        }

        part_len = (array_ptr(uint8_t))uripos - part_start;

        if (part_len) {
            bufpos += coap_put_option(bufpos, end, lastonum, optnum, part_start, part_len);
            lastonum = optnum;
        }
    }

    return bufpos - buf;
}

ssize_t coap_well_known_core_default_handler(coap_pkt_t *pkt atype(ptr(coap_pkt_t)),
                                             uint8_t *buf acount(len),
                                             size_t len)
{
    size_t n;
    array_ptr(uint8_t) payload_end = buf + len;
    array_ptr(uint8_t) payload_start abounds(buf, payload_end)
        = buf + coap_get_total_hdr_len(pkt);
    array_ptr(uint8_t) bufpos abounds(payload_start, payload_end)
        = buf + coap_get_total_hdr_len(pkt);

    n = coap_put_option_ct(bufpos, payload_end, 0, COAP_CT_LINK_FORMAT);
    if (!n)
        return -1;

    bufpos += n;
    *bufpos++ = 0xff;

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (i) {
            *bufpos++ = ',';
        }
        *bufpos++ = '<';
        unsigned url_len = strlen(coap_resources[i].path);
        memcpy(bufpos, coap_resources[i].path, url_len);
        bufpos += url_len;
        *bufpos++ = '>';
    }

    unsigned payload_len = bufpos - payload_start;

    return coap_build_reply(pkt, COAP_CODE_205, buf, len, payload_len);
}
