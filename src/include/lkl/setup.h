/* Portions Copyright (c) 2022 Electronics and Telecommunications Research Institute */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef SETUP_H
#define SETUP_H

#include "shared/sgxlkl_enclave_config.h"

#define DEFAULT_LKL_CMDLINE ""

/* Intialise LKL by booting the kernel */
void lkl_start_init();

/* Mount all LKL disks */
void lkl_mount_disks(
    const sgxlkl_enclave_root_config_t* root,
    const sgxlkl_enclave_mount_config_t* mounts,
    size_t num_mounts,
    const char* cwd);

/* Shutdown the running LKL kernel */
void lkl_terminate(int exit_status);

/* Return if LKL is currently terminating */
bool is_lkl_terminating();

#define ETRI_SYSCALL_CTRL
#ifdef ETRI_SYSCALL_CTRL /** Author: hjk, classact(c) */

/* Environment variable keys and number of syscalls and name size */
// Allowable System call list file input 
#define ALLOW_SYSCALLS      "ALLOW_SYSCALLS="

// System call control enable
#define CTRL_SYSCALL        "CTRL_SYSCALL="

#define SYSCALL_STAT        "SYSCALL_STAT="

#define MAX_LKL_SYSCALLS    440
#define MAX_SYSCALL_LENGTH  30
#define MAX_PATH_LENGTH     256

/* setup.c
   Returns syscall log directory path */
char* get_syscall_log_dir();

/* setup.c
   Return 1 when enable whitelist based system, otherwise false  
   */
int is_syscall_ctrl_enabled(void);

/* setup.c
   If syscall stat report is activated, returns positive number(otherwise <= 0)
   */
int get_syscall_stat_report_config();

/* lkl_util.c
   Set allowable syscalls(whitelist).  */
int set_allowable_syscalls(char *syscalls);


#endif  /** End-Author: hjk, classact(c) */



#endif /* SETUP_H */
