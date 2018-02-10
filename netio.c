/*
 * ryshttpd -- small, plain, fast embedded http server.
 *
 * ryshttpd is copyrighted:
 * Copyright (C) 2018 Andrey Rys. All rights reserved.
 *
 * ryshttpd is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "httpd.h"

static void timespec_diff(const struct timespec *start, const struct timespec *stop, struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000UL;
	}
	else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
	}
}

static void timespec_add(struct timespec *to, const struct timespec *add)
{
	to->tv_sec += add->tv_sec;
	to->tv_nsec += add->tv_nsec;
	if (to->tv_nsec >= 1000000000UL) {
		to->tv_nsec -= 1000000000UL;
		to->tv_sec++;
	}
}

/*
 * Rate limiting is implemented as a simple userspace sleeping.
 * The total limit is determined by a series of sent chunks
 * with a series of added sleeps over them if user was downloading
 * a chunk faster than a single time chunk permitted.
 * Because client here is a simple forked process, it is permitted to sleep.
 */

static void ratelim_calculate(struct rate_limit *rl)
{
	if (rl->calculated == YES) return;
	if (rl->total == NOFSIZE) {
		rl->chunk = 0;
		rl->calculated = YES;
		return;
	}

	if (rl->total < (rh_fsize)rh_rdwr_bufsize) rl->total = (rh_fsize)rh_rdwr_bufsize;
	rl->nr_chk = RATELIM_START_CHUNKS;
	rl->chunk = rl->total / rl->nr_chk;
	while (rl->chunk >= (rh_fsize)rh_rdwr_bufsize) {
		rl->nr_chk *= 2;
		rl->chunk = rl->total / rl->nr_chk;
	}
	rl->calculated = YES;
}

static void ratelim_snapshot_time(struct timespec *tp)
{
	clockid_t clkid;

#ifdef CLOCK_MONOTONIC_RAW
	clkid = CLOCK_MONOTONIC_RAW;
#else
	clkid = CLOCK_MONOTONIC;
#endif
	rh_memzero(tp, sizeof(struct timespec));
	if (clock_gettime(clkid, tp) == -1) xerror("clock_gettime");
}

static size_t io_ratelimit_data(rh_yesno write, struct client_info *clinfo, void *data, size_t szdata, rh_yesno noretry, rh_yesno nosleep)
{
	size_t xszdata = szdata;
	size_t done = 0, t;
	struct rate_limit *rl;
	struct timespec tps, tpd, tdiff;
	rh_yesno do_stop = NO;
	rh_yesno single = YES;

	rl = write ? &clinfo->ralimitdown : &clinfo->ralimitup;
	if (nosleep == NO) ratelim_calculate(rl);

	if (rl->chunk > 0 && xszdata >= rl->chunk) {
		do {
			/* Single chunk or multiple (heavy transfer?) */
			single = NO;
			/* Take start time */
			ratelim_snapshot_time(&tps);

			/* Do send/recv a chunk */
#ifdef WITH_TLS
			if (clinfo->cltls) t = write ?
				  TLS_write(clinfo->cltls, clinfo->clfd,
				data+(szdata-xszdata), rl->chunk)
				: TLS_read(clinfo->cltls, clinfo->clfd,
				data+(szdata-xszdata), rl->chunk);
			else
#endif
			t = write ?
				  io_write_data(clinfo->clfd,
				data+(szdata-xszdata), rl->chunk, noretry, NULL)
				: io_read_data(clinfo->clfd,
				data+(szdata-xszdata), rl->chunk, noretry, NULL);
			if (t == NOSIZE) return NOSIZE;
			if (t < rl->chunk) do_stop = YES;
			/* Record sent/recv'd amount */
			done += t;

			/* Take push/receive time */
			ratelim_snapshot_time(&tpd);
			/* Measure network times */
			timespec_diff(&tps, &tpd, &tdiff);
			/* If chunk push/receive was faster, then force sleep the remaining */
			if (tdiff.tv_sec == 0
			&& tdiff.tv_nsec < RATELIM_TIME_CHUNK(rl->nr_chk)) {
				tps.tv_sec = 0;
				tps.tv_nsec = RATELIM_TIME_CHUNK(rl->nr_chk) - tdiff.tv_nsec;
				nanosleep(&tps, NULL);
			}

			if (do_stop) goto _done;
		} while ((xszdata -= rl->chunk) >= rl->chunk);
	}

	if (xszdata) {
		if (rl->chunk > 0) ratelim_snapshot_time(&tps);
#ifdef WITH_TLS
		if (clinfo->cltls) t = write ?
			  TLS_write(clinfo->cltls, clinfo->clfd,
			data+(szdata-xszdata), xszdata)
			: TLS_read(clinfo->cltls, clinfo->clfd,
			data+(szdata-xszdata), xszdata);
		else
#endif
		t = write ?
			  io_write_data(clinfo->clfd,
			data+(szdata-xszdata), xszdata, noretry, NULL)
			: io_read_data(clinfo->clfd,
			data+(szdata-xszdata), xszdata, noretry, NULL);
		if (t == NOSIZE) return NOSIZE;
		done += t;

		if (rl->chunk > 0) {
			ratelim_snapshot_time(&tpd);
			timespec_diff(&tps, &tpd, &tdiff);
			/* If single chunk, then accumulate it's time and size over calls */
			if (single == YES) {
				/* Save size */
				rl->done += t;
				/* Accumulate time */
				timespec_add(&rl->doneacc, &tdiff);
				/* If chunk size exceeded... */
				if (rl->done >= rl->chunk) {
					/* ... then measure time difference, and sleep remaining */
					if (rl->doneacc.tv_sec == 0
					&& tdiff.tv_nsec < RATELIM_TIME_CHUNK(rl->nr_chk)) {
						tps.tv_sec = 0;
						tps.tv_nsec = RATELIM_TIME_CHUNK(rl->nr_chk) - tdiff.tv_nsec;
						nanosleep(&tps, NULL);
					}
					/* But if limit is not hit, still, reset the counters */
					rl->done = 0;
					rh_memzero(&rl->doneacc, sizeof(struct timespec));
				}
			}
			else {
				if (tdiff.tv_sec == 0
				&& tdiff.tv_nsec < RATELIM_TIME_CHUNK_REM(rl->nr_chk, rl->chunk, xszdata)) {
					tps.tv_sec = 0;
					tps.tv_nsec = RATELIM_TIME_CHUNK_REM(rl->nr_chk, rl->chunk, xszdata) - tdiff.tv_nsec;
					nanosleep(&tps, NULL);
				}
			}
		}
	}

_done:	return done;
}

/*
 * noretry: if returned less than requested, then return the number, otherwise try to get anything
 * nosleep: do not apply the rate limiting mechanism because we're sending headers etc.
 */
size_t io_recv_data(struct client_info *clinfo, void *data, size_t szdata, rh_yesno noretry, rh_yesno nosleep)
{
	return io_ratelimit_data(NO, clinfo, data, szdata, noretry, nosleep);
}

size_t io_send_data(struct client_info *clinfo, const void *data, size_t szdata, rh_yesno noretry, rh_yesno nosleep)
{
	/* yeah, const void * -> void * looks ugly, but saves exec size */
	return io_ratelimit_data(YES, clinfo, (void *)data, szdata, noretry, nosleep);
}
