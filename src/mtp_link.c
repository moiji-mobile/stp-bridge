/* MTP level3 link */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <mtp_data.h>
#include <mtp_level3.h>
#include <cellmgr_debug.h>
#include <counter.h>

#include <string.h>

static struct msgb *mtp_create_sltm(struct mtp_link *link)
{
	const uint8_t test_ptrn[14] = { 'G', 'S', 'M', 'M', 'M', 'S', };
	struct mtp_level_3_hdr *hdr;
	struct mtp_level_3_mng *mng;
	struct msgb *msg = mtp_msg_alloc(link->set);
	uint8_t *data;
	if (!msg)
		return NULL;

	hdr = (struct mtp_level_3_hdr *) msg->l2h;
	hdr->ser_ind = MTP_SI_MNT_REG_MSG;
	hdr->addr = MTP_ADDR(link->link_no % 16, link->set->dpc, link->set->opc);

	mng = (struct mtp_level_3_mng *) msgb_put(msg, sizeof(*mng));
	mng->cmn.h0 = MTP_TST_MSG_GRP;
	mng->cmn.h1 = MTP_TST_MSG_SLTM;
	mng->length = ARRAY_SIZE(test_ptrn);

	data = msgb_put(msg, ARRAY_SIZE(test_ptrn));
	memcpy(data, test_ptrn, ARRAY_SIZE(test_ptrn));

	/* remember the last tst ptrn... once we have some */
	memcpy(link->test_ptrn, test_ptrn, ARRAY_SIZE(test_ptrn));

	return msg;
}

static void mtp_send_sltm(struct mtp_link *link)
{
	struct msgb *msg;

	link->sltm_pending = 1;
	msg = mtp_create_sltm(link);
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate SLTM.\n");
		return;
	}

	mtp_link_submit(link, msg);
}

static void mtp_sltm_t1_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_SLTM_TOUT]);

	if (link->slta_misses == 0) {
		LOGP(DINP, LOGL_ERROR,
		     "No SLTM response. Retrying. Link: %s/%d\n",
		     link->set->name, link->link_no);
		++link->slta_misses;
		mtp_send_sltm(link);
		bsc_schedule_timer(&link->t1_timer, MTP_T1);
	} else {
		LOGP(DINP, LOGL_ERROR,
		     "Two missing SLTAs. Restart link: %s/%d\n",
		     link->set->name, link->link_no);
		bsc_del_timer(&link->t2_timer);
		mtp_link_failure(link);
	}
}

static void mtp_sltm_t2_timeout(void *_link)
{
	struct mtp_link *link = (struct mtp_link *) _link;

	if (!link->set->running) {
		LOGP(DINP, LOGL_INFO,
		     "The linkset is not active. Stopping SLTM now. %s/%d\n",
		     link->set->name, link->link_no);
		return;
	}

	link->slta_misses = 0;
	mtp_send_sltm(link);

	bsc_schedule_timer(&link->t1_timer, MTP_T1);

	if (link->set->sltm_once && link->was_up)
		LOGP(DINP, LOGL_INFO, "Not sending SLTM again as configured.\n");
	else
		bsc_schedule_timer(&link->t2_timer, MTP_T2);
}

int mtp_link_init(struct mtp_link *link)
{
	link->ctrg = rate_ctr_group_alloc(link,
					  mtp_link_rate_ctr_desc(), link->link_no);
	if (!link->ctrg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate rate_ctr.\n");
		return -1;
	}

	link->t1_timer.data = link;
	link->t1_timer.cb = mtp_sltm_t1_timeout;
	link->t2_timer.data = link;
	link->t2_timer.cb = mtp_sltm_t2_timeout;
	return 0;
}

void mtp_link_stop_link_test(struct mtp_link *link)
{
	bsc_del_timer(&link->t1_timer);
	bsc_del_timer(&link->t2_timer);

	link->sltm_pending = 0;
}

void mtp_link_start_link_test(struct mtp_link *link)
{
	mtp_sltm_t2_timeout(link);
}

int mtp_link_slta(struct mtp_link *link, uint16_t l3_len,
		  struct mtp_level_3_mng *mng)
{
	if (mng->length != 14) {
		LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
		return -1;
	}

	if (l3_len != 16) {
		LOGP(DINP, LOGL_ERROR, "Wrongly sized SLTA: %u\n", mng->length);
		return -1;
	}

	if (memcmp(mng->data, link->test_ptrn, sizeof(link->test_ptrn)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Wrong test pattern SLTA\n");
		return -1;
	}

	/* we had a matching slta */
	bsc_del_timer(&link->t1_timer);
	link->sltm_pending = 0;
	link->was_up = 1;

	return 0;
}

void mtp_link_failure(struct mtp_link *link)
{
	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR, "Ignoring failure on blocked link %s/%d.\n",
		     link->set->name, link->link_no);
		return;
	}

	LOGP(DINP, LOGL_ERROR, "Link has failed. Resetting it: %s/%d\n",
	     link->set->name, link->link_no);
	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_ERROR]);
	link->reset(link);
}

void mtp_link_block(struct mtp_link *link)
{
	link->blocked = 1;
	link->shutdown(link);
}

void mtp_link_unblock(struct mtp_link *link)
{
	if (!link->blocked)
		return;
	link->blocked = 0;
	link->reset(link);
}
