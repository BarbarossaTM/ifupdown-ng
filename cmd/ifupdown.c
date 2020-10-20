/*
 * cmd/ifupdown.c
 * Purpose: bring interfaces up or down
 *
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
 * Copyright (c) 2020 Maximilian Wilhelm <max@sdn.clinic>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#define _GNU_SOURCE
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "libifupdown/libifupdown.h"
#include "cmd/multicall.h"

static bool up;

bool
is_ifdown()
{
	if (strstr(argv0, "ifdown") != NULL)
		return true;

	return false;
}


/*
 * Lock handling functions
 */

static int
acquire_state_lock(const char *state_path, const char *lifname)
{
	if (exec_opts.mock || exec_opts.no_lock)
		return -1;

	char lockpath[4096] = {};

	snprintf(lockpath, sizeof lockpath, "%s.%s.lock", state_path, lifname);

	int fd = open(lockpath, O_CREAT | O_WRONLY | O_TRUNC);
	if (fd < 0)
	{
		if (exec_opts.verbose)
			fprintf(stderr, "%s: while opening lockfile %s: %s\n", argv0, lockpath, strerror(errno));
		return -2;
	}

	int flags = fcntl(fd, F_GETFD);
	if (flags < 0)
	{
		close(fd);

		if (exec_opts.verbose)
			fprintf(stderr, "%s: while getting flags for lockfile: %s\n", argv0, strerror(errno));
		return -2;
	}

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
	{
		close(fd);

		if (exec_opts.verbose)
			fprintf(stderr, "%s: while setting lockfile close-on-exec: %s\n", argv0, strerror(errno));
		return -2;
	}

	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET
	};

	if (exec_opts.verbose)
		fprintf(stderr, "%s: acquiring lock on %s\n", argv0, lockpath);

	if (fcntl(fd, F_SETLK, &fl) == -1)
	{
		close(fd);

		if (exec_opts.verbose)
			fprintf(stderr, "%s: while locking lockfile: %s\n", argv0, strerror(errno));
		return -2;
	}

	return fd;
}

static void
release_interfaces(struct lif_dict *selection)
{
	struct lif_node *iter;

	LIF_DICT_FOREACH(iter, selection)
	{
		struct lif_dict_entry *entry = iter->data;
		struct lif_interface *iface = entry->data;

		if (iface->lock_fd > 0)
			close (iface->lock_fd);
	}
}

static bool
lock_interfaces(struct lif_dict *selection)
{
	struct lif_node *iter;

	LIF_DICT_FOREACH(iter, selection)
	{
		struct lif_dict_entry *entry = iter->data;
		struct lif_interface *iface = entry->data;

		int lock_fd = acquire_state_lock(exec_opts.state_file, iface->ifname);
		if (lock_fd == -2)
		{
			fprintf(stderr, "%s: could not acquire exclusive lock for %s: %s\n", argv0, iface->ifname, strerror(errno));
			goto out_err;
		}

		/* Store lock FD to interface */
		iface->lock_fd = lock_fd;
	}

	return true;

out_err:
	release_interfaces(selection);
	return false;
}


/*
 * Interface classification and gathering functions
 */

static bool
skip_interface(struct lif_interface *iface)
{
	if (iface->is_template)
		return false;

	if (iface->has_config_error)
	{
		if (exec_opts.force)
		{
			fprintf(stderr, "%s: (de)configuring interface %s despite config errors\n", argv0, iface->ifname);
			return false;
		}
		else
		{
			fprintf(stderr, "%s: skipping interface %s due to config errors\n", argv0, iface->ifname);
			return true;
		}
	}

	if (exec_opts.force)
		return false;

	if (up && iface->refcount > 0)
	{
		if (exec_opts.verbose)
			fprintf(stderr, "%s: skipping auto interface %s (already configured), use --force to force configuration\n",
				argv0, iface->ifname);
		return true;
	}

	if (!up && iface->refcount == 0)
	{
		if (exec_opts.verbose)
			fprintf(stderr, "%s: skipping auto interface %s (already deconfigured), use --force to force deconfiguration\n",
				argv0, iface->ifname);
		return true;
	}

	return false;
}

#if 0
bool
change_interface(struct lif_interface *iface, struct lif_dict *collection, struct lif_dict *state, const char *ifname)
{
	if (exec_opts.verbose)
	{
		fprintf(stderr, "%s: changing state of interface %s to '%s'\n",
			argv0, ifname, up ? "up" : "down");
	}

	if (!lif_lifecycle_run(&exec_opts, iface, collection, state, ifname, up))
	{
		fprintf(stderr, "%s: failed to change interface %s state to '%s'\n",
			argv0, ifname, up ? "up" : "down");

		if (lockfd != -1)
			close(lockfd);

		return false;
	}
}
#endif

/*
 * Gather interface dependencies recursively
 */
static void
store_iface_and_dependencies(struct lif_dict *selection, struct lif_interface *iface)
{
	if (!lif_dict_add_once (selection, iface->ifname, iface, (lif_dict_cmp_t) strcmp))
		/* Interface already in selection, therefore all dependencies are, too */
		return;

	/* Gather dependencies and add them as well */
	struct lif_node *iter;
	LIF_DICT_FOREACH(iter, iface->depencies)
	{
		struct lif_dict_entry *entry = iter->data;
		struct lif_interface *iface = entry->data;

		// Check if dep ifaces have config_errors
		if (iface->has_config_error)
			{
				if (exec_opts.force)
					fprintf(stderr, "%s: (de)configuring interface %s despite config errors\n", argv0, iface->ifname);

				else
				{
					fprintf(stderr, "%s: skipping interface %s due to config errors\n", argv0, iface->ifname);
					continue;
				}
		}
	}
}

/*
 * Gather all interfaces marked as 'auto' in the configuration
 */
static void
gather_auto_interfaces(struct lif_dict *selection, struct lif_dict *collection, struct match_options *opts)
{
	struct lif_node *iter;

	LIF_DICT_FOREACH(iter, collection)
	{
		struct lif_dict_entry *entry = iter->data;
		struct lif_interface *iface = entry->data;

		if (opts->is_auto && !iface->is_auto)
			continue;

		if (opts->exclude_pattern != NULL &&
		    !fnmatch(opts->exclude_pattern, iface->ifname, 0))
			continue;

		if (opts->include_pattern != NULL &&
		    fnmatch(opts->include_pattern, iface->ifname, 0))
			continue;

		if (skip_interface(iface))
			continue;

		store_iface_and_dependencies(selection, iface);
	}
}

/*
 * Gather interfaces given on the command line
 */
static bool
gather_given_interface(struct lif_dict *selection, struct lif_dict *collection, struct lif_dict *state, int argc, char **argv)
{
	int idx = optind;
	for (; idx < argc; idx++)
	{
		char lifbuf[4096];
		strlcpy(lifbuf, argv[idx], sizeof lifbuf);

		char *lifname = lifbuf;
		char *p;

		if ((p = strchr(lifbuf, '=')) != NULL)
		{
			*p++ = '\0';
			lifname = p;
		}

		struct lif_interface *iface = lif_state_lookup(state, collection, argv[idx]);
		if (iface == NULL)
		{
			struct lif_dict_entry *entry = lif_dict_find(collection, lifname);
			if (entry == NULL)
			{
				fprintf(stderr, "%s: unknown interface %s\n", argv0, argv[idx]);
				return false;
			}

			iface = entry->data;
		}

		if (skip_interface(iface))
			continue;

		store_iface_and_dependencies(selection, iface);
	}

	return true;
}


/*
 * State handling and main
 */

static int
update_state_file_and_exit(int rc, struct lif_dict *state)
{
	if (exec_opts.mock)
	{
		exit(rc);
		return rc;
	}

	if (!lif_state_write_path(state, exec_opts.state_file))
	{
		fprintf(stderr, "%s: could not update %s\n", argv0, exec_opts.state_file);

		exit(EXIT_FAILURE);
		return EXIT_FAILURE;
	}

	exit(rc);
	return rc;
}

int
ifupdown_main(int argc, char *argv[])
{
	up = !is_ifdown();

	struct lif_dict state = {};		/* interface state */
	struct lif_dict collection = {};	/* collection of all interfaces */
	struct lif_dict selection = {};		/* selection of interfaces we have to (de)configure */
	struct lif_interface_file_parse_state parse_state = {
		.collection = &collection,
	};

	lif_interface_collection_init(&collection);

	/* Load state from disk */
	if (!lif_state_read_path(&state, exec_opts.state_file))
	{
		fprintf(stderr, "%s: could not parse %s\n", argv0, exec_opts.state_file);
		return EXIT_FAILURE;
	}

	/* Parse interface file(s) */
	if (!lif_interface_file_parse(&parse_state, exec_opts.interfaces_file))
	{
		fprintf(stderr, "%s: could not parse %s\n", argv0, exec_opts.interfaces_file);
		return EXIT_FAILURE;
	}

	/* Calculate dependecies for all interfaces */
	if (lif_lifecycle_count_rdepends(&exec_opts, &collection) == -1)
	{
		fprintf(stderr, "%s: could not validate dependency tree\n", argv0);
		return EXIT_FAILURE;
	}

	/* Apply compat layer (if configured) */
	if(!lif_compat_apply(&collection))
	{
		fprintf(stderr, "%s: failed to apply compatibility glue\n", argv0);
		return EXIT_FAILURE;
	}

	/* ??? */
	if (!lif_state_sync(&state, &collection))
	{
		fprintf(stderr, "%s: could not sync state\n", argv0);
		return EXIT_FAILURE;
	}

	/* All 'auto' interface */
	if (match_opts.is_auto)
		gather_auto_interfaces(&selection, &collection, &match_opts);

	/* woot? */
	else if (optind >= argc)
		generic_usage(self_applet, EXIT_FAILURE);

	/* Interfaces given via command line */
	else if (!gather_given_interface(&selection, &collection, &state, argc, argv))
		return update_state_file_and_exit(EXIT_FAILURE, &state);

	/* Lock all interfaces we are going to touch */
	if (!lock_interfaces(&selection))
		return update_state_file_and_exit(EXIT_FAILURE, &state);

	/* configure interfaces here */
	

//	if (!change_auto_interfaces(&collection, &state, &match_opts))
//		return update_state_file_and_exit(EXIT_FAILURE, &state);

	release_interfaces(&selection);
	return update_state_file_and_exit(EXIT_SUCCESS, &state);
}

struct if_applet ifup_applet = {
	.name = "ifup",
	.desc = "bring interfaces up",
	.main = ifupdown_main,
	.usage = "ifup [options] <interfaces>",
	.manpage = "8 ifup",
	.groups = { &global_option_group, &match_option_group, &exec_option_group, },
};

struct if_applet ifdown_applet = {
	.name = "ifdown",
	.desc = "take interfaces down",
	.main = ifupdown_main,
	.usage = "ifdown [options] <interfaces>",
	.manpage = "8 ifdown",
	.groups = { &global_option_group, &match_option_group, &exec_option_group, },
};
