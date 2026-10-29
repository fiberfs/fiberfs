/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_MAIN_H_INCLUDED_
#define _FBR_MAIN_H_INCLUDED_

#define FBR_MOUNT_LOOP_MS		25

struct fbr_main_params {
	struct {
		fbr_bitflag_t		ping;
		fbr_bitflag_t		import;
		fbr_bitflag_t		force;

		size_t			count;
	} commands;

	int				arg_count;
	char				**args;
};

extern int FBR_MAIN_STOP;

void fbr_main_usage(void);
int fbr_main_command(struct fbr_main_params *main_params);

int fiberfs_mount(struct fbr_main_params *main_params);

#endif /* _FBR_MAIN_H_INCLUDED_ */
