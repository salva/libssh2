/* Copyright (C) 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (C) 2009-2010 by Daniel Stenberg
 * Author: Daniel Stenberg <daniel@haxx.se>
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file handles reading and writing to the SECSH transport layer. RFC4253.
 */

#include "libssh2_priv.h"
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#ifdef LIBSSH2DEBUG
#include <stdio.h>
#endif

#include <assert.h>

#include "transport.h"
#include "mac.h"

#define MAX_BLOCKSIZE 32    /* MUST fit biggest crypto block size we use/get */
#define MAX_MACSIZE 64      /* MUST fit biggest MAC length we support */

#ifdef LIBSSH2DEBUG
#define UNPRINTABLE_CHAR '.'
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, const unsigned char *ptr, size_t size)
{
    size_t i;
    size_t c;
    unsigned int width = 0x10;
    char buffer[256];  /* Must be enough for width*4 + about 30 or so */
    size_t used;
    static const char* hex_chars = "0123456789ABCDEF";

    if (!(session->showmask & LIBSSH2_TRACE_TRANS)) {
        /* not asked for, bail out */
        return;
    }

    used = snprintf(buffer, sizeof(buffer), "=> %s (%d bytes)\n",
                    desc, (int) size);
    if (session->tracehandler)
        (session->tracehandler)(session, session->tracehandler_context,
                                buffer, used);
    else
        fprintf(stderr, "%s", buffer);

    for(i = 0; i < size; i += width) {

        used = snprintf(buffer, sizeof(buffer), "%04lx: ", (long)i);

        /* hex not disabled, show it */
        for(c = 0; c < width; c++) {
            if (i + c < size) {
                buffer[used++] = hex_chars[(ptr[i+c] >> 4) & 0xF];
                buffer[used++] = hex_chars[ptr[i+c] & 0xF];
            }
            else {
                buffer[used++] = ' ';
                buffer[used++] = ' ';
            }

            buffer[used++] = ' ';
            if ((width/2) - 1 == c)
                buffer[used++] = ' ';
        }

        buffer[used++] = ':';
        buffer[used++] = ' ';

        for(c = 0; (c < width) && (i + c < size); c++) {
            buffer[used++] = isprint(ptr[i + c]) ?
                ptr[i + c] : UNPRINTABLE_CHAR;
        }
        buffer[used++] = '\n';
        buffer[used] = 0;

        if (session->tracehandler)
            (session->tracehandler)(session, session->tracehandler_context,
                                    buffer, used);
        else
            fprintf(stderr, "%s", buffer);
    }
}
#else
#define debugdump(a,x,y,z)
#endif


/* decrypt() decrypts 'len' bytes from 'source' to 'dest'.
 *
 * returns 0 on success and negative on failure
 */

static int
decrypt(LIBSSH2_SESSION * session, unsigned char *source,
        unsigned char *dest, int len)
{
    int blocksize = session->remote.crypt->blocksize;

    /* if we get called with a len that isn't an even number of blocksizes
       we risk losing those extra bytes */
    assert((len % blocksize) == 0);

    while (len >= blocksize) {
        if (session->remote.crypt->crypt(session, source, blocksize,
                                         &session->remote.crypt_abstract))
            return LIBSSH2_ERROR_DECRYPT;

        /* if the crypt() function would write to a given address it
           wouldn't have to memcpy() and we could avoid this memcpy()
           too */
        memcpy(dest, source, blocksize);

        len -= blocksize;       /* less bytes left */
        dest += blocksize;      /* advance write pointer */
        source += blocksize;    /* advance read pointer */
    }
    return LIBSSH2_ERROR_NONE;         /* all is fine */
}

/*
 * fullpacket() gets called when a full packet has been received and properly
 * collected.
 */
static int
fullpacket(LIBSSH2_SESSION * session, int encrypted /* 1 or 0 */ )
{
    unsigned char macbuf[MAX_MACSIZE];
    struct transportpacket *p = &session->packet;
    int rc;
    int compressed;

    if (session->fullpacket_state == libssh2_NB_state_idle) {
        session->fullpacket_macstate = LIBSSH2_MAC_CONFIRMED;
        session->fullpacket_payload_len = p->packet_length - 1;

        if (encrypted) {

            /* Calculate MAC hash */
            session->remote.mac->hash(session, macbuf,  /* store hash here */
                                      session->remote.seqno,
                                      p->init, 5,
                                      p->payload,
                                      session->fullpacket_payload_len,
                                      &session->remote.mac_abstract);

            /* Compare the calculated hash with the MAC we just read from
             * the network. The read one is at the very end of the payload
             * buffer. Note that 'payload_len' here is the packet_length
             * field which includes the padding but not the MAC.
             */
            if (memcmp(macbuf, p->payload + session->fullpacket_payload_len,
                       session->remote.mac->mac_len)) {
                session->fullpacket_macstate = LIBSSH2_MAC_INVALID;
            }
        }

        session->remote.seqno++;

        /* ignore the padding */
        session->fullpacket_payload_len -= p->padding_length;

        /* Check for and deal with decompression */
        compressed =
            session->local.comp != NULL &&
            session->local.comp->compress &&
            ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
             session->local.comp->use_in_auth);

        if (compressed && session->remote.comp_abstract) {
            /*
             * The buffer for the decompression (remote.comp_abstract) is
             * initialised in time when it is needed so as long it is NULL we
             * cannot decompress.
             */

            unsigned char *data;
            size_t data_len;
            rc = session->remote.comp->decomp(session,
                                              &data, &data_len,
                                              LIBSSH2_PACKET_MAXDECOMP,
                                              p->payload,
                                              session->fullpacket_payload_len,
                                              &session->remote.comp_abstract);
            LIBSSH2_FREE(session, p->payload);
            if(rc)
                return rc;

            p->payload = data;
            session->fullpacket_payload_len = data_len;
        }

        session->fullpacket_packet_type = p->payload[0];

        debugdump(session, "libssh2_transport_read() plain",
                  p->payload, session->fullpacket_payload_len);

        session->fullpacket_state = libssh2_NB_state_created;
    }

    if (session->fullpacket_state == libssh2_NB_state_created) {
        rc = _libssh2_packet_add(session, p->payload,
                                 session->fullpacket_payload_len,
                                 session->fullpacket_macstate);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            return rc;
        if (rc) {
            session->fullpacket_state = libssh2_NB_state_idle;
            return rc;
        }
    }

    session->fullpacket_state = libssh2_NB_state_idle;

    return session->fullpacket_packet_type;
}

static int
refill_read_buffer(LIBSSH2_SESSION * session, int required_len) {
    ssize_t nread;
    struct transportpacket *p = &session->packet;
    int remaining = p->buf_wptr - p->buf_rptr;
    assert(remaining >= 0); /* if remaining turns negative we have a
                             * bad internal error */

    if (remaining >= required_len)
        return remaining;

    /* move any remainder to the start of the buffer so that we can do
       a full refill */
    if (p->buf_rptr != p->buf) {
	memmove(p->buf, p->buf_rptr, remaining);
	p->buf_rptr = p->buf;
	p->buf_wptr = p->buf + remaining;
    }
    else if (p->buf_wptr == p->buf + PACKETBUFSIZE) {
	/* buffer is full, avoid a useless read */
	return remaining;
    }
    
    /* now read a big chunk from the network into the temp buffer */
    nread = LIBSSH2_RECV(session, p->buf_wptr,
                         PACKETBUFSIZE - remaining,
                         LIBSSH2_SOCKET_RECV_FLAGS(session));
    if (nread <= 0) {
        /* check if this is due to EAGAIN and return the special
           return code if so, error out normally otherwise */
        if (nread == -EAGAIN || nread == -EINTR) {
            session->socket_block_directions |=
                LIBSSH2_SESSION_BLOCK_INBOUND;
            return LIBSSH2_ERROR_EAGAIN;
        }
        session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
        _libssh2_debug(session, LIBSSH2_TRACE_SOCKET,
                       "Error recving %d bytes (got %d)",
                       PACKETBUFSIZE - remaining, -nread);
        return LIBSSH2_ERROR_SOCKET_RECV;
    }
    _libssh2_debug(session, LIBSSH2_TRACE_SOCKET,
                   "Recved %d/%d bytes to %p+%d", nread,
                   PACKETBUFSIZE - remaining, p->buf, remaining);
    debugdump(session, "libssh2_transport_read() raw",
              &p->buf[remaining], nread);

    p->buf_wptr += nread; /* advance write pointer */
    return p->buf_wptr - p->buf_rptr;
}

/*
 * _libssh2_transport_read
 *
 * Collect a packet into the input queue.
 *
 * Returns packet type added to input queue or a negative error
 * number.
 */

/*
 * This function reads the binary stream as specified in chapter 6 of RFC4253
 * "The Secure Shell (SSH) Transport Layer Protocol"
 *
 * DOES NOT call _libssh2_error() for ANY error case.
 */
int _libssh2_transport_read(LIBSSH2_SESSION * session)
{
    int rc;
    struct transportpacket *p = &session->packet;
    int payload_missing;
    int buf_available;
    int numdecrypt;
    unsigned char block[MAX_BLOCKSIZE];
    int blocksize;
    size_t payload_length;
    size_t payload_available;

    /* default clear the bit */
    session->socket_block_directions &= ~LIBSSH2_SESSION_BLOCK_INBOUND;

    /*
     * All channels, systems, subsystems, etc eventually make it down here
     * when looking for more incoming data. If a key exchange is going on
     * (LIBSSH2_STATE_EXCHANGING_KEYS bit is set) then the remote end will
     * ONLY send key exchange related traffic. In non-blocking mode, there is
     * a chance to break out of the kex_exchange function with an EAGAIN
     * status, and never come back to it. If LIBSSH2_STATE_EXCHANGING_KEYS is
     * active, then we must redirect to the key exchange. However, if
     * kex_exchange is active (as in it is the one that calls this execution
     * of packet_read, then don't redirect, as that would be an infinite loop!
     */

    if (session->state & LIBSSH2_STATE_EXCHANGING_KEYS &&
        !(session->state & LIBSSH2_STATE_KEX_ACTIVE)) {

        /* Whoever wants a packet won't get anything until the key re-exchange
         * is done!
         */
        _libssh2_debug(session, LIBSSH2_TRACE_TRANS, "Redirecting into the"
                       " key re-exchange from _libssh2_transport_read");
        rc = _libssh2_kex_exchange(session, 1, &session->startup_key_state);
        if (rc)
            return rc;
    }

    if (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED)
        return LIBSSH2_ERROR_SOCKET_DISCONNECT;

    switch(session->readPack_state) {
    case libssh2_NB_state_idle:
        if (session->state & LIBSSH2_STATE_NEWKEYS) {
            p->packet_encrypted = 1;
            blocksize = session->remote.crypt->blocksize;
        } else {
            p->packet_encrypted = 0; /* not encrypted */
            blocksize = 5;      /* not strictly true, but we can use 5 here to
                                   make the checks below work fine still */
        }

        /* read/use a whole big chunk into a temporary area stored in
           the LIBSSH2_SESSION struct. We will decrypt data from that
           buffer into the packet buffer so this temp one doesn't have
           to be able to keep a whole SSH packet, just be large enough
           so that we can read big chunks from the network layer. */
        buf_available = refill_read_buffer(session, blocksize);
        if (buf_available < 0)
            return buf_available;

        if (!p->payload_length) {
            /* ensure no payload buffer has been allocated when payload_length is 0: */
            assert(p->payload == NULL);

            /* No payload package area allocated yet. To know the
               size of this payload, we need to decrypt the first
               blocksize data. */

            if (buf_available < blocksize) {
                /* we can't act on anything less than blocksize, but this
                   check is only done for the initial block since once we have
                   got the start of a block we can in fact deal with fractions
                */
                session->socket_block_directions |=
                    LIBSSH2_SESSION_BLOCK_INBOUND;
                return LIBSSH2_ERROR_EAGAIN;
            }

            if (p->packet_encrypted) {
                rc = decrypt(session, p->buf_rptr, block, blocksize);
                if (rc != LIBSSH2_ERROR_NONE) {
                    session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                    return rc;
                }
                /* save the first 5 bytes of the decrypted package, to be
                   used in the hash calculation later down. */
                memcpy(p->init, p->buf_rptr, 5);
            } else {
                /* the data is plain, just copy it verbatim to
                   the working block buffer */
                memcpy(block, p->buf_rptr, blocksize);
            }

            /* advance the buffer read pointer */
            p->buf_rptr += blocksize;

            /* we now have the initial blocksize bytes decrypted,
             * and we can extract packet and padding length from it
             */
            p->packet_length = _libssh2_ntohu32(block);
            if (p->packet_length < 1) {
                session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                return LIBSSH2_ERROR_DECRYPT;
            }

            p->padding_length = block[4];

            /* payload_length is the number of bytes following the initial
               (5 bytes) packet length and padding length fields */
            payload_length =
                p->packet_length - 1 +
                (p->packet_encrypted ? session->remote.mac->mac_len : 0);

            /* RFC4253 section 6.1 Maximum Packet Length says:
             *
             * "All implementations MUST be able to process
             * packets with uncompressed payload length of 32768
             * bytes or less and total packet size of 35000 bytes
             * or less (including length, padding length, payload,
             * padding, and MAC.)."
             */
            if (payload_length > LIBSSH2_PACKET_MAXPAYLOAD) {
                _libssh2_debug(session, LIBSSH2_TRACE_SOCKET,
                               "Packet too big received (%d bytes), dropping connection", payload_length);
                session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
            }

            /* Get a packet handle put data into. We get one to
               hold all data, including padding and MAC. */
            p->payload = LIBSSH2_ALLOC(session, payload_length);
            if (!p->payload) {
                session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                return LIBSSH2_ERROR_ALLOC;
            }
            p->payload_length = payload_length;
            /* init write pointer to start of payload buffer */
            p->payload_wptr = p->payload;

            if (blocksize > 5) {
                /* copy the data from index 5 to the end of
                   the blocksize from the temporary buffer to
                   the start of the decrypted buffer */
                memcpy(p->payload_wptr, &block[5], blocksize - 5);
                p->payload_wptr += blocksize - 5;       /* advance write pointer */
            }
        }

        while (1) {
            /* number of bytes read so far into the payload */
            payload_available = p->payload_wptr - p->payload;

            /* how much there is left to add to the current payload
               package */
            payload_missing = p->payload_length - payload_available;

            /* have we read the full payload? then go process the packet */
            if (payload_missing == 0)
		break;

            buf_available = refill_read_buffer(session, payload_missing);
	    _libssh2_debug(session, LIBSSH2_TRACE_CONN,
			   "missing data: %d, in buffer: %d",
			   payload_missing, buf_available);

	    if (buf_available < 0)
                return buf_available;

	    
            if (buf_available > payload_missing) {
                /* if we have more data in the buffer than what is going into this
                   particular packet, we limit this round to this packet only */
                buf_available = payload_missing;
            }

            if (p->packet_encrypted) {
                /* At the end of the incoming stream, there is a MAC,
                   and we don't want to decrypt that since we need it
                   "raw". We MUST however decrypt the padding data
                   since it is used for the hash later on. */
                int skip = session->remote.mac->mac_len;

                /* if what we have plus buf_available is bigger than the
                   total minus the skip margin, we should lower the
                   amount to decrypt even more */
                if ((payload_available + buf_available) > (p->payload_length - skip)) {
                    numdecrypt = (p->payload_length - skip) - payload_available;
                } else {
                    int frac;
                    numdecrypt = buf_available;
                    frac = numdecrypt % blocksize;
                    if (frac) {
                        /* not an aligned amount of blocks,
                           align it */
                        numdecrypt -= frac;
                        /* and make it no unencrypted data
                           after it */
                        buf_available = 0;
                    }
                }
            } else {
                /* unencrypted data should not be decrypted at all */
                numdecrypt = 0;
            }

            /* if there are bytes to decrypt, do that */
            if (numdecrypt > 0) {
                /* now decrypt the lot */
                rc = decrypt(session, p->buf_rptr, p->payload_wptr, numdecrypt);
                if (rc != LIBSSH2_ERROR_NONE) {
                    p->payload_length = 0;   /* no packet buffer available */
                    LIBSSH2_FREE(session, p->payload);
                    p->payload = NULL;
                    session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                    return rc;
                }

                /* advance the read pointer */
                p->buf_rptr += numdecrypt;
                /* advance write pointer */
                p->payload_wptr += numdecrypt;

                /* bytes left to take care of without decryption */
                buf_available -= numdecrypt;
            }

            /* if there are bytes to copy that aren't decrypted, simply
               copy them as-is to the target buffer */
            if (buf_available > 0) {
                memcpy(p->payload_wptr, p->buf_rptr, buf_available);

                /* advance the buffer read pointer */
                p->buf_rptr += buf_available;
                /* advance the payload write pointer */
                p->payload_wptr += buf_available;
            }
        }

    case libssh2_NB_state_jump1:
        /* we have a full packet */

        rc = fullpacket(session, p->packet_encrypted);
        if (rc == LIBSSH2_ERROR_EAGAIN) {

            if (session->packAdd_state != libssh2_NB_state_idle)
            {
                /* fullpacket only returns LIBSSH2_ERROR_EAGAIN if
                 * libssh2_packet_add returns LIBSSH2_ERROR_EAGAIN. If that
                 * returns LIBSSH2_ERROR_EAGAIN but the packAdd_state is idle,
                 * then the packet has been added to the brigade, but some
                 * immediate action that was taken based on the packet
                 * type (such as key re-exchange) is not yet complete.
                 * Clear the way for a new packet to be read in.
                 */
                session->readPack_state = libssh2_NB_state_jump1;
            }
            return rc;
        }

        p->payload = NULL; /* payload has been eaten by fullpacket */
        p->payload_length = 0; /* no packet buffer available */
        session->readPack_state = libssh2_NB_state_idle;

        return rc;

    default:
        _libssh2_debug(session, LIBSSH2_TRACE_TRANS,
                       "Internal error, state %d not handled",
                       session->readPack_state);
        break;
    }
    return LIBSSH2_ERROR_SOCKET_RECV; /* we never reach this point */
}

/*
 * _libssh2_transport_read_drain
 *
 * Reads as many packets as possible from the network without blocking.
 * Returns error code (usually LIBSSH2_ERROR_EAGAIN).
 */

int _libssh2_transport_read_drain(LIBSSH2_SESSION *session) {
    int rc;
    do {
        rc = _libssh2_transport_read(session);
    } while (rc >= 0);
    return rc;
}

/*
 * _libssh2_transport_send_ready
 *
 * Checks if, in the current session state, it is safe to call
 * _libssh2_transport_send with a new load.
 *
 * It returns false when a previous call to _libssh2_transport_send
 * was interrupted with an EAGAIN error.
 */
int _libssh2_transport_send_ready(LIBSSH2_SESSION *session)
{
    return (session->packet.olen == 0);
}

static int
send_existing(LIBSSH2_SESSION *session)
{
    struct transportpacket *p = &session->packet;
    ssize_t length = p->ototal_num - p->osent;
    ssize_t rc = LIBSSH2_SEND(session, &p->outbuf[p->osent],
                              length,
                              LIBSSH2_SOCKET_SEND_FLAGS(session));

    if (rc < 0) {
        _libssh2_debug(session, LIBSSH2_TRACE_SOCKET,
                       "Error sending %d bytes, errno: %d", length, -rc);
        /* nothing was sent */
        if (rc != -EAGAIN && rc != -EINTR) {
            /* It was a fatal error, mark the socket as disconnected */
            session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
            return LIBSSH2_ERROR_SOCKET_SEND;
        }
    }
    else {
        _libssh2_debug(session, LIBSSH2_TRACE_SOCKET,
                       "Sent %d/%d bytes at %p+%d", rc, length, p->outbuf, p->osent);
        debugdump(session, "libssh2_transport_write send()",
                  &p->outbuf[p->osent], rc);

        p->osent += rc; /* we sent away this much data */
        if  (rc >= length) {
            /* the remainder of the package was sent */
            p->ototal_num = 0;
            p->olen = 0;
            p->odata = NULL;
            session->socket_block_directions &= ~LIBSSH2_SESSION_BLOCK_OUTBOUND;
            return LIBSSH2_ERROR_NONE;
        }
    }
    session->socket_block_directions |= LIBSSH2_SESSION_BLOCK_OUTBOUND;
    return LIBSSH2_ERROR_EAGAIN;
}

/*
 * libssh2_transport_send
 *
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure.
 *
 * The data is provided as _two_ data areas that are combined by this
 * function.  The 'data' part is sent immediately before 'data2'. 'data2' may
 * be set to NULL to only use a single part.
 *
 * Returns LIBSSH2_ERROR_EAGAIN if it would block or if the whole packet was
 * not sent yet. If it does so, the caller should call this function again as
 * soon as it is likely that more data can be sent, and this function MUST
 * then be called with the same argument set (same data pointer and same
 * data_len) until ERROR_NONE or failure is returned.
 *
 * This function DOES NOT call _libssh2_error() on any errors.
 */
int _libssh2_transport_send(LIBSSH2_SESSION *session,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *data2, size_t data2_len)
{
    int blocksize =
        (session->state & LIBSSH2_STATE_NEWKEYS) ?
        session->local.crypt->blocksize : 8;
    int padding_length;
    size_t packet_length;
    int total_length;
#ifdef RANDOM_PADDING
    int rand_max;
    int seed = data[0];         /* FIXME: make this random */
#endif
    struct transportpacket *p = &session->packet;
    int encrypted;
    int compressed;
    int rc;
    const unsigned char *orgdata = data;
    size_t orgdata_len = data_len;

    /*
     * If the last read operation was interrupted in the middle of a key
     * exchange, we must complete that key exchange before continuing to write
     * further data.
     *
     * See the similar block in _libssh2_transport_read for more details.
     */
    if (session->state & LIBSSH2_STATE_EXCHANGING_KEYS &&
        !(session->state & LIBSSH2_STATE_KEX_ACTIVE)) {
        /* Don't write any new packets if we're still in the middle of a key
         * exchange. */
        _libssh2_debug(session, LIBSSH2_TRACE_TRANS, "Redirecting into the"
                       " key re-exchange from _libssh2_transport_send");
        rc = _libssh2_kex_exchange(session, 1, &session->startup_key_state);
        if (rc)
            return rc;
    }

    debugdump(session, "libssh2_transport_write plain", data, data_len);
    if(data2)
        debugdump(session, "libssh2_transport_write plain2", data2, data2_len);

    /* Check if we have a pending write to complete */
    if (p->olen) {
        /* When we are about to complete the sending of a packet, it is vital
           that the caller doesn't try to send a new/different packet since
           we don't add this one up until the previous one has been sent. To
           make the caller really notice his/hers flaw, we return error for
           this case.
           Only sanity-check data and data_len and not data2 and data2_len!!
        */
        if ((data != p->odata) || (data_len != p->olen))
            return LIBSSH2_ERROR_BAD_USE;

        return send_existing(session);
    }

    encrypted = (session->state & LIBSSH2_STATE_NEWKEYS) ? 1 : 0;

    compressed =
        session->local.comp != NULL &&
        session->local.comp->compress &&
        ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
         session->local.comp->use_in_auth);

    if (encrypted && compressed) {
        /* the idea here is that these function must fail if the output gets
           larger than what fits in the assigned buffer so thus they don't
           check the input size as we don't know how much it compresses */
        size_t dest_len = MAX_SSH_PACKET_LEN-5-256;
        size_t dest2_len = dest_len;

        /* compress directly to the target buffer */
        rc = session->local.comp->comp(session,
                                       &p->outbuf[5], &dest_len,
                                       data, data_len,
                                       &session->local.comp_abstract);
        if(rc) {
            session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
            return rc;     /* compression failure */
        }

        if(data2 && data2_len) {
            /* compress directly to the target buffer right after where the
               previous call put data */
            dest2_len -= dest_len;

            rc = session->local.comp->comp(session,
                                           &p->outbuf[5+dest_len], &dest2_len,
                                           data2, data2_len,
                                           &session->local.comp_abstract);
        }
        else
            dest2_len = 0;

        if(rc) {
            session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
            return rc;     /* compression failure */
        }

        data_len = dest_len + dest2_len; /* use the combined length */
    }
    else {
        if((data_len + data2_len) >= (MAX_SSH_PACKET_LEN-0x100))
            /* too large packet, return error for this until we make this
               function split it up and send multiple SSH packets */
            return LIBSSH2_ERROR_INVAL;

        /* copy the payload data */
        memcpy(&p->outbuf[5], data, data_len);
        if(data2 && data2_len)
            memcpy(&p->outbuf[5+data_len], data2, data2_len);
        data_len += data2_len; /* use the combined length */
    }


    /* RFC4253 says: Note that the length of the concatenation of
       'packet_length', 'padding_length', 'payload', and 'random padding'
       MUST be a multiple of the cipher block size or 8, whichever is
       larger. */

    /* Plain math: (4 + 1 + packet_length + padding_length) % blocksize == 0 */

    packet_length = data_len + 1 + 4;   /* 1 is for padding_length field
                                           4 for the packet_length field */

    /* at this point we have it all except the padding */

    /* first figure out our minimum padding amount to make it an even
       block size */
    padding_length = blocksize - (packet_length % blocksize);

    /* if the padding becomes too small we add another blocksize worth
       of it (taken from the original libssh2 where it didn't have any
       real explanation) */
    if (padding_length < 4) {
        padding_length += blocksize;
    }
#ifdef RANDOM_PADDING
    /* FIXME: we can add padding here, but that also makes the packets
       bigger etc */

    /* now we can add 'blocksize' to the padding_length N number of times
       (to "help thwart traffic analysis") but it must be less than 255 in
       total */
    rand_max = (255 - padding_length) / blocksize + 1;
    padding_length += blocksize * (seed % rand_max);
#endif

    packet_length += padding_length;

    /* append the MAC length to the total_length size */
    total_length =
        packet_length + (encrypted ? session->local.mac->mac_len : 0);

    /* store packet_length, which is the size of the whole packet except
       the MAC and the packet_length field itself */
    _libssh2_htonu32(p->outbuf, packet_length - 4);
    /* store padding_length */
    p->outbuf[4] = (unsigned char)padding_length;

    /* fill the padding area with random junk */
    _libssh2_random(p->outbuf + 5 + data_len, padding_length);

    if (encrypted) {
        size_t i;

        /* Calculate MAC hash. Put the output at index packet_length,
           since that size includes the whole packet. The MAC is
           calculated on the entire unencrypted packet, including all
           fields except the MAC field itself. */
        session->local.mac->hash(session, p->outbuf + packet_length,
                                 session->local.seqno, p->outbuf,
                                 packet_length, NULL, 0,
                                 &session->local.mac_abstract);

        /* Encrypt the whole packet data, one block size at a time.
           The MAC field is not encrypted. */
        for(i = 0; i < packet_length; i += session->local.crypt->blocksize) {
            unsigned char *ptr = &p->outbuf[i];
            if (session->local.crypt->crypt(session, ptr,
                                            session->local.crypt->blocksize,
                                            &session->local.crypt_abstract)) {
                session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                return LIBSSH2_ERROR_ENCRYPT;     /* encryption failure */
            }
        }
    }

    session->local.seqno++;
    p->odata = orgdata;
    p->olen = orgdata_len;
    p->osent = 0;
    p->ototal_num = total_length;

    return send_existing(session);
}
