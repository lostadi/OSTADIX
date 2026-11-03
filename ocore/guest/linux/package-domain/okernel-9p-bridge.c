/* Process/FD glue for original u9fs and Plan9port 9pserve. No 9P codec lives
 * here. Production exports only the existing native /n/okernel mount. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef OKERNEL_BRIDGE_TEST_ROOT
#define EXPORT_ROOT OKERNEL_BRIDGE_TEST_ROOT
#else
#define EXPORT_ROOT "/n/okernel"
#endif

static volatile sig_atomic_t stopping;
static pid_t exporter = -1, multiplexer = -1;

static void interrupted(int signal_number) { (void)signal_number; stopping = 1; }
static int path(char *out, size_t size, const char *directory, const char *name) {
    int length = snprintf(out, size, "%s/%s", directory, name);
    return length >= 0 && (size_t)length < size;
}
static int child_list_path(char *out, size_t size) {
#ifdef OKERNEL_BRIDGE_TEST_CHILDREN_PATH
    int length = snprintf(out, size, "%s", OKERNEL_BRIDGE_TEST_CHILDREN_PATH);
#else
    int length = snprintf(out, size, "/proc/self/task/%ld/children", (long)getpid());
#endif
    return length >= 0 && (size_t)length < size;
}
static int child_ownership_available(void) {
    char list[128];
    if (!child_list_path(list, sizeof(list))) return 0;
    FILE *children = fopen(list, "r");
    if (!children) return 0;
    /* An empty list is expected before launch; an unreadable interface is an
     * error. Never replace kernel child ownership with process-name/PID guesses. */
    (void)fgetc(children);
    int valid = !ferror(children);
    fclose(children);
    return valid;
}
static int native_mount(void) {
    struct stat status;
    if (lstat(EXPORT_ROOT, &status) || !S_ISDIR(status.st_mode)) return 0;
#ifdef OKERNEL_BRIDGE_TEST_ROOT
    fputs("HOST COMPONENT PROBE: private test tree; no native mount qualification\n", stderr);
    return 1;
#else
    FILE *mounts = setmntent("/proc/mounts", "r");
    if (!mounts) return 0;
    struct mntent *entry;
    int found = 0;
    while ((entry = getmntent(mounts))) {
        if (!strcmp(entry->mnt_fsname, "okernel") && !strcmp(entry->mnt_dir, EXPORT_ROOT)
                && !strcmp(entry->mnt_type, "9p") && hasmntopt(entry, "trans=virtio")) found = 1;
    }
    endmntent(mounts);
    return found;
#endif
}
static int trusted_directory(const char *directory) {
    struct stat status;
    return !lstat(directory, &status) && S_ISDIR(status.st_mode)
        && status.st_uid == geteuid() && (status.st_mode & 0777) == 0700;
}
static unsigned long long start_time(void) {
    FILE *stream = fopen("/proc/self/stat", "r");
    char buffer[4096];
    if (!stream || !fgets(buffer, sizeof(buffer), stream)) {
        if (stream) fclose(stream);
        return 0;
    }
    fclose(stream);
    char *fields = strrchr(buffer, ')');
    if (!fields) return 0;
    fields += 2;
    for (int field = 3; field < 22; field++) {
        fields = strchr(fields, ' ');
        if (!fields) return 0;
        fields++;
    }
    return strtoull(fields, NULL, 10);
}
static int stale_socket(const char *socket_path) {
    struct stat status;
    if (lstat(socket_path, &status)) return errno == ENOENT;
    if (!S_ISSOCK(status.st_mode) || status.st_uid != geteuid()) return 0;
    return unlink(socket_path) == 0;
}
static pid_t launch(const char *program, char *const arguments[], int channel, int other,
                    int lock, pid_t parent) {
    pid_t child = fork();
    if (child != 0) return child;
    /* If this supervisor unexpectedly dies, its private original processes
     * must not remain as unmanaged service listeners. */
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent) _exit(126);
    signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
    close(other); close(lock);
    if (dup2(channel, STDIN_FILENO) < 0 || dup2(channel, STDOUT_FILENO) < 0) _exit(126);
    if (channel > STDERR_FILENO) close(channel);
    execv(program, arguments);
    perror(program);
    _exit(127);
}
static void cleanup_children(void) {
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        /* Original libthread backgrounds 9pserve. As a Linux subreaper we own
         * that daemon after its initial parent exits, including its changed
         * process group. Never infer ownership from a stale recorded PID. */
        char list[128];
        if (!child_list_path(list, sizeof(list))) return;
        FILE *children = fopen(list, "r");
        long child;
        if (children) {
            while (fscanf(children, "%ld", &child) == 1)
                if (child > 0) kill((pid_t)child, attempt < 50 ? SIGTERM : SIGKILL);
            fclose(children);
        }
        pid_t done;
        do { done = waitpid(-1, NULL, WNOHANG); } while (done > 0);
        if (done < 0 && errno == ECHILD) return;
        struct timespec delay = {0, 100000000};
        nanosleep(&delay, NULL);
    }
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
}
int main(int argc, char **argv) {
    if (argc != 3) {
        fputs("usage: okernel-9p-bridge PLAN9_PREFIX PRIVATE_RUNTIME_DIRECTORY\n", stderr);
        return 2;
    }
    if (!child_ownership_available()) {
        fputs("The kernel child-ownership interface is unavailable; CONFIG_PROC_CHILDREN and mounted procfs are required before starting original services.\n", stderr);
        return 1;
    }
    if (!native_mount()) {
        fputs("The fixed native okernel 9P mount is absent; refusing to export a fallback directory.\n", stderr);
        return 1;
    }
    if (!trusted_directory(argv[2])) {
        fputs("The service runtime must be an owned, real directory with mode 0700.\n", stderr);
        return 1;
    }
    /* Pin the mount before starting either original process. Future pathname
     * replacement/unmount must not turn this service into a fallback export. */
    int root_handle = open(EXPORT_ROOT, O_PATH | O_DIRECTORY | O_NOFOLLOW);
    if (root_handle < 0) { perror("pin native namespace"); return 1; }
#ifndef OKERNEL_BRIDGE_TEST_ROOT
    struct statfs filesystem;
    if (fstatfs(root_handle, &filesystem) || filesystem.f_type != 0x01021997) {
        fputs("Pinned export is not the native 9P filesystem.\n", stderr);
        close(root_handle); return 1;
    }
#endif
    char pinned_root[64];
    snprintf(pinned_root, sizeof(pinned_root), "/proc/self/fd/%d", root_handle);
    char server[PATH_MAX], mux[PATH_MAX], socket_path[PATH_MAX], lock_path[PATH_MAX];
    char pid_path[PATH_MAX], log_path[PATH_MAX], endpoint[PATH_MAX + 6];
    if (!path(server, sizeof(server), argv[1], "bin/u9fs")
            || !path(mux, sizeof(mux), argv[1], "bin/9pserve")
            || !path(socket_path, sizeof(socket_path), argv[2], "okernel")
            || !path(lock_path, sizeof(lock_path), argv[2], "supervisor.lock")
            || !path(pid_path, sizeof(pid_path), argv[2], "supervisor.pid")
            || !path(log_path, sizeof(log_path), argv[2], "u9fs.log")
            || strlen(socket_path) >= 104 || access(server, X_OK) || access(mux, X_OK)) {
        fputs("Original u9fs/9pserve tools are missing or the service path is too long.\n", stderr);
        return 1;
    }
    snprintf(endpoint, sizeof(endpoint), "unix!%s", socket_path);
    umask(077);
    int lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) {
        fputs("The native namespace bridge is already supervised or its lock is unavailable.\n", stderr);
        if (lock >= 0) close(lock);
        return 1;
    }
    if (!stale_socket(socket_path)) {
        fputs("Preserving an unrelated service-path entry.\n", stderr); close(lock); return 1;
    }
    int pid_file = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    unsigned long long started = start_time();
    if (pid_file < 0 || length < 0 || !started) {
        perror("supervisor identity"); if (pid_file >= 0) close(pid_file); close(lock); return 1;
    }
    executable[length] = 0;
    if (dprintf(pid_file, "%ld\n%llu\n%s\n", (long)getpid(), started, executable) < 0 || fsync(pid_file)) {
        perror("supervisor record"); close(pid_file); unlink(pid_path); close(lock); return 1;
    }
    close(pid_file);
    struct passwd *user = getpwuid(geteuid());
    int channels[2];
    if (!user || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channels)) {
        perror("bridge socketpair/user"); unlink(pid_path); close(lock); return 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = interrupted; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL); sigaction(SIGHUP, &action, NULL);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1)) {
        perror("original service subreaper"); close(channels[0]); close(channels[1]);
        unlink(pid_path); close(lock); return 1;
    }
    unsetenv("NOLIBTHREADDAEMONIZE"); unsetenv("LIBTHREAD");
    char *server_args[] = {server, "-n", "-a", "none", "-u", user->pw_name,
                          "-m", "8192", "-l", log_path, pinned_root, NULL};
    char *mux_args[] = {mux, "-n", endpoint, NULL};
    pid_t parent = getpid();
    exporter = launch(server, server_args, channels[0], channels[1], lock, parent);
    if (exporter > 0) multiplexer = launch(mux, mux_args, channels[1], channels[0], lock, parent);
    close(channels[0]); close(channels[1]);
    close(root_handle);
    int result = 1;
    if (exporter > 0 && multiplexer > 0) {
        fprintf(stderr, "Native namespace bridge supervisor=%ld u9fs=%ld 9pserve=%ld root=%s\n",
                (long)parent, (long)exporter, (long)multiplexer, EXPORT_ROOT);
        int announced = 0;
        while (!stopping) {
            int status;
            pid_t done = waitpid(-1, &status, 0);
            if (done == exporter) { exporter = -1; break; }
            if (done == multiplexer && WIFEXITED(status) && WEXITSTATUS(status) == 0 && !announced) {
                announced = 1; continue;
            }
            if (done > 0) break;
            if (done < 0 && errno != EINTR) break;
        }
        if (stopping) result = 0;
    } else perror("fork original server");
    cleanup_children();
    /* A client disappears when the owned original processes exit. Do not
     * remove arbitrary files in place of their service socket. */
    (void)stale_socket(socket_path);
    unlink(pid_path);
    close(lock);
    return result;
}
