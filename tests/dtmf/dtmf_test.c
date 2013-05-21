/*
 * (C) 2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2012 by On-Waves
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

#include <dtmf_scheduler.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(got,want) \
	if (got != want) { \
		fprintf(stderr, "Values should be the same 0x%x 0x%x at %s:%d\n", \
			got, want, __FILE__, __LINE__); \
		abort(); \
	}

static void test_queue_while_play(void)
{
	struct dtmf_state state;
	char tone[sizeof(state.tones) + 1];
	unsigned int len = 0;

	dtmf_state_init(&state);

	ASSERT(dtmf_state_add(&state, 'a'), 0);
	ASSERT(dtmf_state_add(&state, 'b'), 0);
	ASSERT(dtmf_state_add(&state, 'c'), 0);

	len = dtmf_state_get_pending(&state, tone);
	ASSERT(len, 3);
	ASSERT(strlen(tone), 3);
	ASSERT(state.playing, 1);
	ASSERT(strcmp(tone, "abc"), 0);

	ASSERT(dtmf_state_add(&state, 'd'), 0);
	dtmf_state_played(&state);
	ASSERT(state.playing, 0);

	len = dtmf_state_get_pending(&state, tone);
	ASSERT(len, 1);
	ASSERT(strlen(tone), 1);
	ASSERT(state.playing, 1);
	ASSERT(strcmp(tone, "d"), 0);

	ASSERT(state.playing, 1);
	dtmf_state_played(&state);
	ASSERT(state.playing, 0);

	/* and check that nothing is played */
	len = dtmf_state_get_pending(&state, tone);
	ASSERT(len, 0);
	ASSERT(strlen(tone), 0);
	ASSERT(state.playing, 0);
}

static void test_queue_over_flow(void)
{
	struct dtmf_state state;
	const size_t max_items = sizeof(state.tones);
	char tone[sizeof(state.tones) + 1];
	int i;
	unsigned int len;

	dtmf_state_init(&state);

	/* add everything that should fit.. */
	for (i = 0; i < max_items; ++i) {
		ASSERT(dtmf_state_add(&state, 'a' + i), 0);
	}

	/* this should fail */
	ASSERT(dtmf_state_add(&state, 'Z'), -1);

	/* read all of it */
	len = dtmf_state_get_pending(&state, tone);
	ASSERT(len, max_items);
	ASSERT(strlen(tone), max_items);
	for (i = 0; i < strlen(tone); ++i)
		ASSERT(tone[i], 'a' + i);
	ASSERT(state.playing, 1);
	dtmf_state_played(&state);
	ASSERT(state.playing, 0);
}


int main(int argc, char **argv)
{
	test_queue_while_play();
	test_queue_over_flow();
	printf("All tests passed.\n");
	return 0;
}
