// Portions Copyright (c) 2022 Electronics and Telecommunications Research Institute
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdarg.h>
#include <stdlib.h>

#include "enclave/enclave_util.h"

// Integer base 2 logarithm.
int int_log2(unsigned long long arg)
{
    int l = 0;
    while (arg >>= 1)
        l++;
    return l;
}

#ifdef DEBUG

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

#include <enclave/lthread.h>
#include <openenclave/internal/print.h>
#include "lkl_host.h"
#include "lkl/setup.h"

#define EPOLL_EVENT_FLAG_BUFFER_LEN 256

#undef __LKL_SYSCALL
#define __LKL_SYSCALL(nr) {(const char*)(__lkl__NR_##nr), #nr},
#include <lkl.h>
static const char* __lkl_syscall_names[][2] = {
#include <lkl/syscalls.h>
    {NULL, NULL},
#undef __LKL_SYSCALL
};

#ifdef ETRI_SYSCALL_CTRL    /* Author: hjk, classact(c) */

#define TIME_FORMAT_LENGTH  22
// syscall stat
typedef struct syscall_stat_st {
    const char* name;   /* __lkl_syscall_names[][1] */
    int count;
    char udt[TIME_FORMAT_LENGTH];
} syscall_stat;

static syscall_stat syscall_stat_tlb[MAX_LKL_SYSCALLS];

static const char *undefined = "undefined\0";

// syscall whitelist table
static char whitelist[MAX_LKL_SYSCALLS][MAX_SYSCALL_LENGTH];

/** func: equal
  * desc: If given strings(char *) are equal, return 1, otherwise 0
  * arg0: (char *)str1
  * arg1: (char *)str2
  * returns: (int)  1: equal, 0: not equal
  */
int equal(const char *str1, char *str2) {
    int str1_length, str2_length;

    if (str1 == NULL || str2 == NULL) {
        return 0;
    }
    str1_length = strlen(str1);
    str2_length = strlen(str2);

    int cmp_length = 0;
    if (str1_length > str2_length) {
        cmp_length = str2_length;
    }
    else {
        cmp_length = str1_length;
    }
    if (cmp_length <= 0){
        return 0;
    }

    if (!strncmp(str1, str2, cmp_length)) {
        return 1;
    }
    return 0;
}

/** func: is_exist_in_whitelist
  * desc: check whether name is exist in whitelist
  * arg0: (char *)name; system call symbol name
  * returns: (int) 1: exist, 0: not exist
  */
int is_exist_in_whitelist(char* name) {
    int i;
    int found = 0;

    // find called syscall name in whitelist
    for(i=0; i < MAX_LKL_SYSCALLS; i++) {
        if(whitelist[i][0] == 0x00) {
            break;
        }
        if(equal(name, whitelist[i])) {
            found = 1;
            break;
        }
    }
    return found;
}


/** func: append_to_whitelist
  * desc: append symbol name to whitelist
  * arg0: (char *)name; system call symbol name
  * returns: (int) 1: success, 0: fail
  */
int append_to_whitelist(char* name) {
    int index = -1;
    int i;
    int name_len;
    
    if(name == NULL) {
        lkl_printf("[[ ETRI_LOG:WARN ]] Null symbol name.\n");
        return 0;
    }

    if(is_exist_in_whitelist(name)) {
        lkl_printf("[[ ETRI_LOG:WARN ]] Ignore duplicated exist symbol.\n");
        return 0;
    }

    // find null row index
    for(i=0; i < MAX_LKL_SYSCALLS; i++) {
        if(whitelist[i][0] == 0x00) {
            index = i;
            break;
        }
    } 
    if (index < 0) {
        lkl_printf("[[ ETRI_LOG:WARN ]] No empty slot in whitelist.\n");
        return 0;
    }
    
    name_len = strlen(name);
    if(name_len > MAX_SYSCALL_LENGTH) {
        lkl_printf("[[ ETRI_LOG:WARN ]] Invalid symbol name length(%s, len=%d).\n", name, name_len);
        return 0;
    }    
    strncpy(whitelist[index], name, name_len);
    return 1;
}


/** func: set_allowable_syscalls
  * desc: set allowable syscalls(whitelist)
  * arg0: (char *)whitelist; allowable system call filename
  * returns: (int) 1: success, 0: fail
  */
int set_allowable_syscalls(char *syscalls) {
    int i, retval=0;
    char* token;    

    // lkl_printf("calls set_allowable_syscalls\n");
    if (syscalls == NULL) {
        return 0;
    }

    for(i=0; i<MAX_LKL_SYSCALLS; i++) {
        memset(whitelist[i], 0x00, MAX_SYSCALL_LENGTH);
    }

    token = strtok(syscalls, ":");
    lkl_printf("Append first token(%s)\n", token);
    retval = append_to_whitelist(token);
    if (retval) {
        lkl_printf("[[ ETRI_LOG:INFO ]] Append %s to whitelist\n", token);
    }    
    
    while(token != NULL) {    
        token = strtok(NULL, ":");
        if(token == NULL) break;        
        retval = append_to_whitelist(token);
        if (retval) {
            lkl_printf("[[ ETRI_LOG:INFO ]] Append %s to whitelist\n", token);
        }
        else {
            lkl_printf("[[ ETRI_LOG:WARN ]] %s is already existed in whitelist\n", token);
        }        
    }
    return 1;
}

/** 
 *  func: print_lkl_syscalls
 *  desc: print entire lkl_syscalls from "/sgx-lkl/build_musl/sgx-lkl-musl/include/lkl/syscalls.h"
 *  arg0: (void)
 *  return: (void)
 */
void print_lkl_syscalls(void) {
    lkl_printf("------------------------------------------------------------------\n");
    for (int i = 0; __lkl_syscall_names[i][1] != NULL; i++)
    {
        lkl_printf("%d\t%s\n", __lkl_syscall_names[i][0], __lkl_syscall_names[i][1]);
    }
    lkl_printf("------------------------------------------------------------------\n");
}


/** 
 *  func: init_syscall_stat
 *  desc: initialize syscall stat table
 *  arg0: (void)
 *  return: (void)
 */
void init_syscall_stat(void) {    
    // Setup symbol table
    for(int n = 0; n < MAX_LKL_SYSCALLS; n++) {
        syscall_stat_tlb[n].count = 0;
        syscall_stat_tlb[n].name = NULL;

        for (int i = 0; __lkl_syscall_names[i][1] != NULL; i++) {
            if ((long)__lkl_syscall_names[i][0] == n) {
                syscall_stat_tlb[n].name = __lkl_syscall_names[i][1];
                if(syscall_stat_tlb[n].name == NULL) {
                    syscall_stat_tlb[n].name = undefined;
                }
            }
        }
    }    
}

int disallow = 0;
int _first = 1;
const char *disallow_call = NULL;
int disallow_call_number = -1;
int reserve_disallow_abort = -1;

/** 
 *  func: print_syscall_stat
 *  desc: print system call statistics(call count)
 *        If t is less than 1, do not print anything
 *  arg0: (int) t; 1 call per every __sgxlkl_log_syscall t calls
 *  return: (void)
 */
void print_syscall_stat(int t) {
    static unsigned int count = 0;
    if(t <= 0) return;    

    if((count % t) == 0) {
        for (int n = 0; n < MAX_LKL_SYSCALLS; n++) {
            if(syscall_stat_tlb[n].count != 0) {
                if (equal(syscall_stat_tlb[n].name, (char *) disallow_call)) {
                    lkl_printf("[[ ETRI_LOG:STAT ]] [#%4u] %20s(%3d): %6d calls [## DISALLOW ]\n", 
                                count/t, disallow_call, disallow_call_number, 1);
                    reserve_disallow_abort = 1;
                }
                else {
                    lkl_printf("[[ ETRI_LOG:STAT ]] [#%4u] %20s(%3d): %6d calls [## ALLOW ]\n", 
                                count/t, syscall_stat_tlb[n].name, n, syscall_stat_tlb[n].count);
                }
            }
        }
    }
    if(count++ >= 4.29E+09) count = 0;
}


/** 
 *  func: __sgxlkl_log_syscall
 *  desc: print syscall and control syscall
 *  arg0: (void)
 *  return: (void)
 */
long __sgxlkl_log_syscall(
    sgxlkl_syscall_kind type,
    long n,
    long res,
    int params_len,
    ...)
{
    const char* name = NULL;
    // const char* call;    
    int i;
    static int first = 1;
    static int syscall_ctrl_enable = -1;
    static int stat_report_config = -1;
    int matched=0;

    // time_t t = time(NULL);   : no support syscall in enclave    

    if (!sgxlkl_trace_ignored_syscall && type == SGXLKL_IGNORED_SYSCALL)
        return res;

    if (!sgxlkl_trace_unsupported_syscall && type == SGXLKL_UNSUPPORTED_SYSCALL)
        return res;

    if (!sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL)
        return res;

    if (!sgxlkl_trace_internal_syscall && type == SGXLKL_INTERNAL_SYSCALL)
        return res;
    
    if (first) {
        // Setup system control and report statistics
        stat_report_config = get_syscall_stat_report_config();
        init_syscall_stat();
        syscall_ctrl_enable = is_syscall_ctrl_enabled();
        if (syscall_ctrl_enable < 0) {
            // Exit application with error
            sgxlkl_fail("[ ETRI_LOG ] ERROR: Abort unauthorized execution(0xff01).\n");
        }
        first = 0;
    }

    // Get symbol name with system call number
    for (i = 0; __lkl_syscall_names[i][1] != NULL; i++)
    {
        if ((long)__lkl_syscall_names[i][0] == n)
        {
            name = __lkl_syscall_names[i][1];
            break;
        }
    }
     
    // System call control statement based on whitelist
    // Constrainst:
    // If system call symbol name is not defiend in sgxlkl, 
    // name is represented as NULL, accodingly allow NULL system call
    // to preserve right application's runtime
    if (syscall_ctrl_enable == 1 && name != NULL) {
        if(reserve_disallow_abort == 1) {
            sgxlkl_fail("[ ETRI_LOG ] ERROR: Abort application(unauthorized system call)\n");
        }
        // Find out syscall name from whitelist
        matched = 0;
        for(i=0; i < MAX_LKL_SYSCALLS; i++) {
            if(whitelist[i][0] == 0x00) {
                break;
            }            
            if(equal(name, whitelist[i])) {
                matched=1;
                break;
            }
        }
        if(!matched) {
            disallow_call = name;
            disallow_call_number = n;
            lkl_printf("not matched: name = %s n=%d\n", name, n);
        }        
    }

    // Accumulate system call count
    if(n > 0 && n < MAX_LKL_SYSCALLS) {
        syscall_stat_tlb[n].count++;
    }
    print_syscall_stat(stat_report_config);       

    return res;
}

#else /* If not defined ETRI_SYSCALL_CTRL */

static void parse_epoll_event_flags(
    char* buf,
    size_t buf_len,
    struct epoll_event* evt)
{
    size_t written = 0;
    if (evt->events & EPOLLIN)
    {
        written = snprintf(buf, buf_len - written, "EPOLLIN");
        buf += written;
    }
    if (evt->events & EPOLLOUT)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLOUT", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLRDHUP)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLRDHUP", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLPRI)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLPRI", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLERR)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLERR", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLHUP)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLHUP", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLET)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLET", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLONESHOT)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLONESHOT", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLWAKEUP)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLWAKEUP", written ? "|" : "");
        buf += written;
    }

    buf[0] = '\0';
}

long __sgxlkl_log_syscall(
    sgxlkl_syscall_kind type,
    long n,
    long res,
    int params_len,
    ...)
{
    const char* name = NULL;
    char errmsg[255] = {0};

    if (!sgxlkl_trace_ignored_syscall && type == SGXLKL_IGNORED_SYSCALL)
        return res;

    if (!sgxlkl_trace_unsupported_syscall && type == SGXLKL_UNSUPPORTED_SYSCALL)
        return res;

    if (!sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL)
        return res;

    if (!sgxlkl_trace_internal_syscall && type == SGXLKL_INTERNAL_SYSCALL)
        return res;

    long params[6] = {0};
    va_list valist;
    va_start(valist, params_len);
    for (int i = 0; i < params_len; i++)
    {
        params[i] = va_arg(valist, long);
    }
    va_end(valist);

    for (int i = 0; __lkl_syscall_names[i][1] != NULL; i++)
    {
        if ((long)__lkl_syscall_names[i][0] == n)
        {
            name = __lkl_syscall_names[i][1];
            break;
        }
    }

    if (name == NULL)
        name = "### INVALID ###";
    if (res < 0)
        snprintf(errmsg, sizeof(errmsg), " (%s) <--- !", lkl_strerror(res));

    int tid = lthread_self() ? lthread_self()->tid : 0;
    if (type == SGXLKL_REDIRECT_SYSCALL)
    {
        // n is x64 syscall number, name is not available.
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] \t%ld\t(%ld, %ld, %ld, %ld, %ld, %ld) = %ld%s\n",
            tid,
            n,
            params[0],
            params[1],
            params[2],
            params[3],
            params[4],
            params[5],
            res,
            errmsg);
    }
    else if (n == SYS_newfstatat)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_openat)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_execve)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%s, %s, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            (const char*)(params[0]),
            ((const char**)params[1])[0],
            ((const char**)params[1])[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_statx)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            params[4],
            res,
            errmsg);
    }
    else if (n == SYS_epoll_ctl)
    {
        char event_flags[EPOLL_EVENT_FLAG_BUFFER_LEN];
        struct epoll_event* evt = (struct epoll_event*)params[3];
        parse_epoll_event_flags(event_flags, EPOLL_EVENT_FLAG_BUFFER_LEN, evt);
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%d, %d, %d, %p {%s}) = %ld %s\n",
            tid,
            name,
            n,
            (int)params[0],
            (int)params[1],
            (int)params[2],
            evt,
            event_flags,
            res,
            errmsg);
    }
    else if (n == SYS_epoll_pwait)
    {
        char event_flags[EPOLL_EVENT_FLAG_BUFFER_LEN];
        struct epoll_event* evt = (struct epoll_event*)params[1];
        parse_epoll_event_flags(event_flags, EPOLL_EVENT_FLAG_BUFFER_LEN, evt);
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%d, %p {%s}, %d, %d, %ld) = %ld %s\n",
            tid,
            name,
            n,
            (int)params[0],
            evt,
            event_flags,
            (int)params[2],
            (int)params[3],
            params[4],
            res,
            errmsg);
    }
    else
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %ld, %ld, %ld, %ld, %ld) = %ld%s\n",
            tid,
            name,
            n,
            params[0],
            params[1],
            params[2],
            params[3],
            params[4],
            params[5],
            res,
            errmsg);
    }
    return res;
}

#endif /* ETRI_SYSCALL_CTRL */

#endif /* DEBUG */
