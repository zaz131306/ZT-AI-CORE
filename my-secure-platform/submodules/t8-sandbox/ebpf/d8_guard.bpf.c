// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// =============================================================================
// ZT-AI-CORE v2.4 — eBPF-страж песочницы D8 (F-E-03)
//
// Второй рубеж изоляции ПОСЛЕ SECCOMP (defense in depth):
//   1. cgroup/sock_create — блокировка AF_INET/AF_INET6/AF_NETLINK/AF_PACKET
//      для cgroup D8 (AC-01: socket(AF_INET) из D8 -> eBPF drop, даже если
//      SECCOMP-профиль каким-то образом обойдён);
//   2. cgroup/unix_connect — разрешение connect(2) по AF_UNIX ТОЛЬКО к
//      sun_path из каталога /run/zt-core/ (F-E-04: валидация sun_path).
//
// Сборка:  ebpf/build.sh   (clang -target bpf)
// Подключение (cgroup v2, на хосте):
//   bpftool prog load d8_guard.o /sys/fs/bpf/zt/d8_guard
//   bpftool cgroup attach /sys/fs/cgroup/<d8-cgroup> sock_create \
//       pinned /sys/fs/bpf/zt/d8_guard_sock_create
//   bpftool cgroup attach /sys/fs/cgroup/<d8-cgroup> unix_connect \
//       pinned /sys/fs/bpf/zt/d8_guard_unix_connect
//
// Примечание о лицензии: секция license="GPL" требуется ядру для ряда
// BPF-хелперов; данная программа хелперы не использует и логически является
// частью проекта Apache-2.0 (двойное лицензирование GPL-2.0 OR Apache-2.0).
// =============================================================================

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef memset
#define memset(s, c, n) __builtin_memset((s), (c), (n))
#endif

// Семейства сокетов (include/linux/socket.h)
#define AF_UNIX    1
#define AF_INET    2
#define AF_INET6   10
#define AF_NETLINK 16
#define AF_PACKET  17

// Вердикты cgroup-хуков
#define BPF_DROP 0
#define BPF_OK   1

// Разрешённый префикс sun_path (F-E-04: IPC только через шину zt-core)
static const char ALLOWED_PREFIX[] = "/run/zt-core/";
#define ALLOWED_PREFIX_LEN 13   // sizeof("/run/zt-core/") - 1
#define SUN_PATH_MAX 108

// -----------------------------------------------------------------------------
// Контекст BPF_CGROUP_SOCK_CREATE (include/uapi/linux/bpf.h, struct bpf_sock)
// -----------------------------------------------------------------------------
struct zt_bpf_sock {
    __u32 bound_dev_if;
    __u32 family;
    __u32 type;
    __u32 protocol;
};

// -----------------------------------------------------------------------------
// Контекст BPF_CGROUP_UNIX_CONNECT (struct bpf_sock_addr, поле user_path)
// Объявляем самостоятельно, чтобы не зависеть от vmlinux.h/libbpf-заголовков.
// -----------------------------------------------------------------------------
struct zt_bpf_sock_addr {
    __u32 user_family;
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 msg_src_ip4;
    __u32 msg_src_ip6[4];
    char  user_path[SUN_PATH_MAX];   // sockaddr_un.sun_path
    __u32 user_path_len;
};

// -----------------------------------------------------------------------------
// Хук 1: создание сокетов в cgroup D8
// Разрешён ТОЛЬКО AF_UNIX. AF_INET/AF_INET6 — явный drop (AC-01);
// AF_NETLINK/AF_PACKET — drop (обход изоляции raw/netlink-трафиком).
// -----------------------------------------------------------------------------
SEC("cgroup/sock_create")
int d8_guard_sock_create(struct zt_bpf_sock *ctx)
{
    __u32 family = ctx->family;

    if (family == AF_INET || family == AF_INET6)
        return BPF_DROP;
    if (family == AF_NETLINK || family == AF_PACKET)
        return BPF_DROP;
    if (family != AF_UNIX)
        return BPF_DROP;   // неизвестное семейство — default deny (zero-trust)

    return BPF_OK;
}

// -----------------------------------------------------------------------------
// Хук 2: connect(2) по AF_UNIX — валидация sun_path (F-E-04)
// Разрешены только пути вида /run/zt-core/<name>.sock.
// Всё прочее (включая относительные пути и abstract-namespace '\0...') — drop.
// -----------------------------------------------------------------------------
SEC("cgroup/unix_connect")
int d8_guard_unix_connect(struct zt_bpf_sock_addr *ctx)
{
    char path[SUN_PATH_MAX];
    int i;

    // Abstract-namespace сокеты (sun_path[0] == '\0') запрещены:
    // их нельзя верифицировать по пути.
    if (ctx->user_path[0] == '\0')
        return BPF_DROP;

    // Копируем путь из контекста (bounded access для верификатора).
    memset(path, 0, sizeof(path));
    for (i = 0; i < SUN_PATH_MAX; i++) {
        path[i] = ctx->user_path[i];
        if (path[i] == '\0')
            break;
    }

    // Проверка префикса /run/zt-core/
    #pragma unroll
    for (i = 0; i < ALLOWED_PREFIX_LEN; i++) {
        if (path[i] != ALLOWED_PREFIX[i])
            return BPF_DROP;
    }

    // После префикса должно быть имя файла, оканчивающееся на ".sock"
    {
        int len = 0;
        int j;
        for (j = ALLOWED_PREFIX_LEN; j < SUN_PATH_MAX; j++) {
            if (path[j] == '\0')
                break;
            len++;
        }
        if (len < 6)   // минимум: "x.sock"
            return BPF_DROP;
        // суффикс ".sock"
        #pragma unroll
        for (i = 0; i < 5; i++) {
            if (path[ALLOWED_PREFIX_LEN + len - 5 + i] != ".sock"[i])
                return BPF_DROP;
        }
        // запрещаем вложенные пути и traversal
        for (j = ALLOWED_PREFIX_LEN; j < ALLOWED_PREFIX_LEN + len - 5; j++) {
            if (path[j] == '/' || path[j] == '.')
                return BPF_DROP;
        }
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0x020400;   // ZT-AI-CORE v2.4
