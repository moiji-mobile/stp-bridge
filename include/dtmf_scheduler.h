#ifndef DTMF_SCHEDULER_H
#define DTMF_SCHEDULER_H

/**
 * The state/queue for DTMF signalling.
 */
struct dtmf_state {
	int size;		/* <! The last tone to play */
	char tones[24];		/* <! Pending tones */
	int playing;		/* <! Playing a tone right now? */
};

/* initialize */
void dtmf_state_init(struct dtmf_state *state);

/* add a tone to the list */
int dtmf_state_add(struct dtmf_state *state, char tone);

/* tones that should be played, playing will be set to 1 */
unsigned int dtmf_state_get_pending(struct dtmf_state *state, char *tones);

/* call when the playout is done */
void dtmf_state_played(struct dtmf_state *state);

unsigned int dtmf_tones_queued(struct dtmf_state *state);

#endif
