/**
 * @file application_changes_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example application that uses sysrepo as the configuration datastore. It
 * prints the changes made in running data store.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include "sysrepo.h"
#include "sysrepo/xpath.h"
#include "sysrepo/values.h"

volatile int exit_application = 0;

#define XPATH_MAX_LEN 100

static void
print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val) {
    switch(op) {
    case SR_OP_CREATED:
        if (NULL != new_val) {
           printf("CREATED: ");
           sr_print_val(new_val);
        }
        break;
    case SR_OP_DELETED:
        if (NULL != old_val) {
           printf("DELETED: ");
           sr_print_val(old_val);
        }
	break;
    case SR_OP_MODIFIED:
        if (NULL != old_val && NULL != new_val) {
           printf("MODIFIED: ");
           printf("old value ");
           sr_print_val(old_val);
           printf("new value ");
           sr_print_val(new_val);
        }
	break;
    case SR_OP_MOVED:
        if (NULL != new_val) {
            printf("MOVED: %s after %s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
        }
	break;
    }
}

const char *
ev_to_str(sr_notif_event_t ev) {
    switch (ev) {
    case SR_EV_VERIFY:
        return "verify";
    case SR_EV_APPLY:
        return "apply";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}

static int
modify_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    sr_xpath_ctx_t xp_ctx = {0};
    char change_path[XPATH_MAX_LEN] = {0};
    char action[100] = "unknown";
    char cmd[500] = "";
    char *val = NULL, *dst = NULL, *seg1 = NULL;

    printf("%d: notification, event [%s], module_name [%s]\n", __LINE__, ev_to_str(event), module_name);
    if (event == SR_EV_VERIFY) {
        return SR_ERR_OK;
    } else if (event == SR_EV_APPLY) {
        snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);
        rc = sr_get_changes_iter(session, change_path , &it);
        if (SR_ERR_OK != rc) {
            printf("Get changes iter failed for xpath %s", change_path);
            goto end;
        }

        while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
        
            print_change(oper, old_value, new_value);

            // Find operation
            if (oper == SR_OP_CREATED || oper == SR_OP_MODIFIED) {
                strcpy(action, "add");
                value = new_value;
            } else if (oper == SR_OP_DELETED) {
                strcpy(action, "del");
                value = old_value;
            } else {
                // NOP
            }
            
            // Find destination
            // /srv6-explicit-path:srv6-explicit-path/path[destination='2222:4::2']/destination
            val = sr_xpath_key_value((char*)value->xpath, "path", "destination", &xp_ctx);
            if (val != NULL) {
                dst = strdup(val);
            }
            sr_xpath_recover(&xp_ctx);

            // Only 1 segment is supported, if multiple are present, last one is used
            if (strcmp(value->xpath, "/srv6-explicit-path:srv6-explicit-path/srv6-segment") == 0) {
                strcpy(seg1, sr_val_to_str(value));
            }

            // Only 1 segment is supported, if multiple are present, last one is used
            // /srv6-explicit-path:srv6-explicit-path/path[destination='2222:4::2']/sr-path/srv6-segment
            if (strcmp(sr_xpath_node_name(value->xpath), "srv6-segment") == 0) {
                seg1 = strdup(sr_val_to_str(value));
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        // ip -6 route add 2222:4::2 via 2222:3::2 encap seg6 mode encap segs 2222:3::2 mtu 1436
        cmd[0] = 0;
        if (strcmp(action, "add") == 0) {
            sprintf(cmd, "ip -6 route add %s via %s encap seg6 mode encap segs %s mtu 1436", dst, seg1, seg1);
        } else if (strcmp(action, "del") == 0) {
            sprintf(cmd, "ip -6 route del %s", dst);
        } else {
            printf("%d: unknown action\n", __LINE__);
        }
        if (cmd[0] != 0) {
            rc = system(cmd);
            printf("executed, rc [%d], cmd [%s]\n", rc, cmd);
        }
    } else {
        printf("%d: unknown event received [%d]\n", __LINE__, event);
    }

end:
    if (dst != NULL) free(dst);
    if (seg1 != NULL) free(seg1);
    if (it != NULL) sr_free_change_iter(it);
    return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    char *module_name = "srv6-explicit-path";

    if (argc > 1) {
        module_name = argv[1];
    } else {
        printf("\nYou can pass the module name to be subscribed as the first argument\n");
    }

    printf("Application will watch for changes in %s\n", module_name);
    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* subscribe for changes in running config */
    rc = sr_module_change_subscribe(session, module_name, modify_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}

