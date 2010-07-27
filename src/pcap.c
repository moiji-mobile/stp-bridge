/* PCAP code from OpenBSC done by Holger Freyther */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <mtp_pcap.h>

#include <sys/time.h>

#include <unistd.h>

#define static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1];

/*
 * pcap writing of the misdn load
 * pcap format is from http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
struct pcap_hdr {
	u_int32_t magic_number;
	u_int16_t version_major;
	u_int16_t version_minor;
	int32_t  thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t network;
} __attribute__((packed));

struct pcaprec_hdr {
	u_int32_t ts_sec;
	u_int32_t ts_usec;
	u_int32_t incl_len;
	u_int32_t orig_len;
} __attribute__((packed));

int mtp_pcap_write_header(int fd)
{
	static struct pcap_hdr hdr = {
		.magic_number	= 0xa1b2c3d4,
		.version_major	= 2,
		.version_minor	= 4,
		.thiszone	= 0,
		.sigfigs	= 0,
		.snaplen	= 65535,
		.network	= 141,
	};

	return write(fd, &hdr, sizeof(hdr));
}

int mtp_pcap_write_msu(int fd, const u_int8_t *data, int length)
{
	int rc_h, rc_d;
	struct timeval tv;
	struct pcaprec_hdr payload_header = {
		.ts_sec	    = 0,
		.ts_usec    = 0,
		.incl_len   = length,
		.orig_len   = length,
	};

	gettimeofday(&tv, NULL);
	payload_header.ts_sec = tv.tv_sec;
	payload_header.ts_usec = tv.tv_usec;

	rc_h = write(fd, &payload_header, sizeof(payload_header));
	rc_d = write(fd, data, length);

	return rc_h == sizeof(payload_header) && rc_d == length;
}
