/*
 * Copyright (c) 2009-2011, The Regents of the University of California,
 * through Lawrence Berkeley National Laboratory (subject to receipt of any
 * required approvals from the U.S. Dept. of Energy).  All rights reserved.
 *
 * This code is distributed under a BSD style license, see the LICENSE file
 * for complete information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <stdint.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_client_api.h"
#include "iperf_server_api.h"
#include "iperf_units.h"
#include "iperf_locale.h"
#include "iperf_error.h"
#include "iperf_net.h"

u32     iperf_debug_level = 0xf;

int iperf_run(struct iperf_test *);

/**************************************************************************/
//TODO list:
// duration: int 

int
tls_perf(void* data)
{
    struct iperf_test *test;
	struct tht_param* tht = (struct tht_param*)data;
/* check Help command or wrong parma */


    // XXX: Setting the process affinity requires root on most systems.
    //      Is this a feature we really need?
    test = iperf_new_test();
    if (!test) {
        iperf_error("create new test error");
        return (-1);
    }
    iperf_defaults(test);	/* sets defaults */
	//printf("main, local = %s\n", test->bind_address);
	iperf_init_test_wm(test, tht);

    if (iperf_run(test) < 0) {
		iperf_error("error");
		iperf_free_test(test);		
        return (-1);
    }

    iperf_free_test(test);

    IPF_DBG("\niperf Done.\n");
	printf("\niperf Done.\n");

    return (0);
}

/**************************************************************************/
int
iperf_run(struct iperf_test * test)
{
    switch (test->role) {
        case 's':
#if !TLS_IPERF_AUTO_TEST
            for (;;) 
#endif 
			{
                if (iperf_run_server(test) < 0) {
                    iperf_error("error");
                }
                iperf_reset_test(test);
            }
            break;
        case 'c':
            if (iperf_run_client(test) < 0) {
                iperf_error("error");
                return (-1);
            }

            break;
        default:
            usage();
            break;
    }

    return (0);
}

