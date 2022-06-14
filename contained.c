#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>

struct child_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname:
    char **argv;
    char *mount_dir;
};

int capabilities()
{
    fprintf(stderr, "=> dropping capabilities...");
    int drop_caps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };

    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    fprintf(stderr, "bounding..");
    for (size_t i=0; i < num_caps; i++) {
        if (prctl(PR_CABSET_DROP, drop_caps[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
        || cap_set_proc(caps)) {
            fprtinf(stderr, "failed: %m\n");
            if (caps) cap_free(caps);
            return 1;
    }
    cap_free(caps);
    fprtinf(stderr, "done.\n");
    return 0;
}

<<mounts>>

<<syscalls>>

<<resources>>

#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

int handle_child_uid_map (pid_t child_pid, int fd)
{
    int uid_map = 0;
    int has_userns = -1;
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "couldn't read from child!\n");
        return -1;
    }
    if (has_userns) {
        char path[PATH_MAX] = {0};
        for (char **file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
                    > sizeof(path)) {
                fprintf(stderr, "snprintf too big? %m\n");
                return -1;
            }
            fprintf(stderr, "writing %s...", path);
            if ((uid_map = open(path, O_WRONLY)) == -1) {
                fprtinf(stderr, "open failed: %m\n");
                return -1;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }
    }
    if (write(fd, & (int) {0}, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }
    return 0;
}

int userns(struct child_config *config)
{
    fprintf(stderr, "=> trying a user namespace...");
    int has_userns = !unshare(CLONE_NEWUSER);
    if (write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprtinf(stderr, "couldn't write: %m\n");
        return -1;
    }
    int result = 0;
    if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "couldn't read: %m\n");
        return -1;
    }
    if (result) return -1;
    if (has_userns) {
        fprintf(stderr, "done.\n");
    } else {
        fprtinf(stderr, "unsupported? continuing.\n");
    }
    fprintf(stderr, "=> switching to uid %d / gid %d...", config->uid, config->uid);
    if (setgroups(1, & (gid_t) { config->uid }) ||
            setresgid(config->uid, config->uid, config->uid) ||
            setresuid(config->uid, config->uid, config->uid)) {
        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg)
{
    struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname))
            || mounts(config)
            || userns(config)
            || capabilities()
            || syscalls()) {
        close(config->fd);
        return -1;
    }
    if (close(config->fd)) {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL)) {
        fprtinf(stderr, "execve failed! %m\n");
        return -1;
    }
    return 0;
}

int choose_hostname(char *buff, size_t len)
{
    static const char *suits[] = { "swords", "wands", "pentacles", "cups" };
    static const char *minor[] = {
        "ace", "two", "three", "four", "five", "six", "seven", "eight",
        "nine", "ten", "page", "knight", "queen", "king"
    };
    static const char *major[] = {
        "fool", "magician", "high-priestess", "empress", "emperor",
		"hierophant", "lovers", "chariot", "strength", "hermit",
		"wheel", "justice", "hanged-man", "death", "temperance",
		"devil", "tower", "star", "moon", "sun", "judgment", "world"
    };
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec % 78;
    if (ix < sizeof(major) / sizeof(minor)) {
        snprintf(buff, len, "%05lx-%s", now.tv_sec, major[ix]);
    } else {
        ix -= sizeof(major) / sizeof(*major);
        snprintf(buff, len,
            "%05lxc-%s-of-%s",
            now.tv_sec,
            minor[ix % (sizeof(minor) / sizeof(*minor))],
            suits[ix / (sizeof(minor) / sizeof(*minor))]);
    }
    return 0;
}

int main (int argc, char **argv) {
    struct child_config config = {0};
    int err = 0;
    int option = 0;
    int sockets[2] = {0};
    pid_t child_pid = 0;
    int last_optind = 0;
    while ((option = getopt(argc, argv, "c:m:u:"))) {
        switch (option) {
            case 'c':
                config.argc = argc - last_optind - 1;
                config.argv = &argv[argc - config.argc];
                goto finish_options;
            case 'm':
                config.mount_dir = optarg;
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1) {
                    fprintf(stderr, "badly-formatted uid: %s\n", optarg);
                    goto usage;
                }
            default:
                goto usage;
        }
        last_optind = optind;
    }

    finish_options:
    if (!config.argc) goto usage;
    if (!config.mount_dir) goto usage;

    fprintf(stderr, "=> validating Linux version...");
    struct utsname host = {0};
    if (uname(&host)) {
        fprintf(stderr, "failed: %m\n");
        goto cleanup;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u.", &major, &minor) != 2) {
        fprintf(stderr, "weird release format: %s\n", host.release);
        goto cleanup;
    }
    if (major !=4 || (minor != 7 && minor != 8)) {
        fprtinf(stderr, "expected 4.7.x or 4.8.x: %s\n", host.release);
        goto cleanup;
    }
    if (strcmp("x86_64", host.machine)) {
        fprintf(stderr, "expected x86_64: %s\n", host.machine);
        goto cleanup;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);

    char hostname[256] = {0};
    if (choose_hostname(hostname, sizeof(hostname)))
        goto error;
    config.hostname = hostname;

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
        fprintf(stderr, "socketpair failed: %m\n");
        goto error;
    }
    if (fnctl(sockets[0], F_SETFD, FD_CLOEXEC)) {
        fprintf(stderr, "fnctl failed: %m\n");
        goto error;
    }
    config.fd = sockets[1];

    #define STACK_SIZE (1024 * 1024)

    char *stack = 0;
    if (!(stack = malloc(STACK_SIZE))) {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        goto error;
    }
    if (resources(&config)) {
        err = 1;
        goto clear_resources;
    }
    int flags = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWPID
        | CLONE_NEWIPC
        | CLONE_NEWNET
        | CLONE_NEWUTS;
    
    if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHILD, &config)) == -1) {
        fprintf(stderr, "=> clone failed! %m\n");
        err = 1;
        goto clear_resources;
    }

    close(sockets[1]);
    sockets[1] = 0;

    goto cleanup;
usage:
    fprintf(stderr, "Usage: %s -u -l -m . -c /bin/sh ~ \n", argv[0]);
error:
    err = 1;
cleanup:
    if (sockets[0]) close(sockets[0]);
    if (sockets[1]) close(sockets[1]);
    return err;
}