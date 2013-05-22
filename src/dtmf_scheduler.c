/*
 * (C) 2012-2013 by Holger Hans Peter Freyther
 * (C) 2012-2013 by On-Waves
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

#include "dtmf_scheduler.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

void dtmf_state_init(struct dtmf_state *state)
{
	memset(state, 0, sizeof(*state));
}

int dtmf_state_add(struct dtmf_state *state, char tone)
{
	/* we would override the head */
	if (state->size == sizeof(state->tones))
		return -1;
	/* avoid someone adding a NULL byte */
	if (tone == 0)
		return -2;

	state->tones[state->size++] = tone;
	return 0;
}

char dtmf_state_pop_tone(struct dtmf_state *state)
{
	char res;

	if (state->size == 0)
		return CHAR_MAX;

	res = state->tones[0];
	state->size -= 1;
	memmove(&state->tones[0], &state->tones[1], state->size);
	return res;
}

unsigned int dtmf_state_get_pending(struct dtmf_state *state, char *tones)
{
	int pos;

	for (pos = 0; pos < state->size; ++pos)
		tones[pos] = state->tones[pos];

	/* consume everything up to the tail */
	state->size = 0;

	/* remember that we play things */
	if (pos > 0)
		state->playing = 1;
	tones[pos] = '\0';
	return pos;
}

void dtmf_state_played(struct dtmf_state *state)
{
	state->playing = 0;
}

void dtmf_state_play(struct dtmf_state *state)
{
	state->playing = 1;
}

unsigned int dtmf_tones_queued(struct dtmf_state *state)
{
	return state->size;
}
