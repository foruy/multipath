#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "test.h"

#define GENLMSG_DATA(glh) ((void *)((char *)(NLMSG_DATA(glh)) + GENL_HDRLEN))
#define NLA_DATA(na)      ((void *)((char *)(na) + NLA_HDRLEN))

typedef struct nlmsg {
	struct nlmsghdr n;
	struct genlmsghdr g;
	struct packet pack;
} nlmsg;

int genl_send_msg(int fd, u16t nlmsg_type, u32t nlmsg_pid,
                  byte genl_cmd, byte genl_version, u16t nla_type,
                  void *nla_data, int nla_len)
{
    struct nlattr *na;
    struct sockaddr_nl nladdr;
    int r, buflen;
    char *buf;
    nlmsg msg;

    msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    msg.n.nlmsg_type = nlmsg_type;
    msg.n.nlmsg_flags = NLM_F_REQUEST;
    msg.n.nlmsg_seq = 0;
    msg.n.nlmsg_pid = nlmsg_pid;
    msg.g.cmd = genl_cmd;
    msg.g.version = genl_version;
    na = (struct nlattr *) GENLMSG_DATA(&msg);
    na->nla_type = nla_type;
    na->nla_len = nla_len + NLA_HDRLEN;
    memcpy(NLA_DATA(na), nla_data, nla_len);
    msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    buf = (char *) &msg;
    buflen = msg.n.nlmsg_len;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    while ((r = sendto(fd, buf, buflen, 0, (struct sockaddr *) &nladdr, sizeof(nladdr))) < buflen) {
        if (r > 0) {
            buf += r;
            buflen -= r;
        } else if (errno != EAGAIN) {
            return -1;
        }
    }
    return 0;
}

static int get_fid(int fd, const char *fname)
{
    nlmsg ans;
    int id = 0, rc;
    struct nlattr *na;
    int rep_len;

    rc = genl_send_msg(fd, GENL_ID_CTRL, 0,
                       CTRL_CMD_GETFAMILY, 1,
                       CTRL_ATTR_FAMILY_NAME,
                       (void *)fname,
                       strlen(fname) + 1);
	if (rc < 0)
		goto ret;

    rep_len = recv(fd, &ans, sizeof(ans), 0);
    if (rep_len < 0 || ans.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&ans.n), rep_len))
        goto ret;

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID)
        id = *(__u16 *) NLA_DATA(na);
ret:
    return id;
}

static int set_pid(int fd, u16t fid)
{
    u32t pid = getpid();
    return genl_send_msg(fd, fid, pid, CG_CMD_PID, 1, CG_ATTR_PID, (void *) &pid, sizeof(u32t));
}

int rcv_msg(u16t fid, int sock, struct packet *data)
{
	int ret;
	nlmsg msg;
	struct nlattr *na;

	ret = recv(sock, &msg, sizeof(msg), 0);
	if (ret < 0 || msg.n.nlmsg_type == NLMSG_ERROR ||
			msg.n.nlmsg_type != fid || fid == 0)
		return -1;

	na = (struct nlattr *) GENLMSG_DATA(&msg);
        *data = *(struct packet *) NLA_DATA(na);
	return 0;
}

int snd_msg(u16t fid, int fd, struct packet *data)
{
	return genl_send_msg(fd, fid, getpid(), CG_CMD_PACKET, 1, CG_ATTR_PACKET, (void *) data, sizeof(struct packet));
}

int rcv_string_msg(int fid, int sock, char **string)
{
    int ret;
    nlmsg msg;
    struct nlattr *na;

    ret = recv(sock, &msg, sizeof(msg), 0);
    if (ret < 0)
        goto err;

    if (msg.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&msg.n), ret))
        goto err;

    if (msg.n.nlmsg_type == fid && fid != 0) {
        na = (struct nlattr *) GENLMSG_DATA(&msg);
        *string = (char *) NLA_DATA(na);
        return 0;
    }

err:
    return -1;
}

int rcv_int_msg(int fid, int sock, unsigned long *result)
{
    int ret;
    nlmsg msg;
    struct nlattr *na;

    ret = recv(sock, &msg, sizeof(msg), 0);
    if (ret < 0)
        goto err;

    if (msg.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&msg.n), ret))
        goto err;

    if (msg.n.nlmsg_type == fid && fid != 0) {
        na = (struct nlattr *) GENLMSG_DATA(&msg);
        *result = *(unsigned long *) NLA_DATA(na);
        return 0;
    }

err:
    return -1;
}

int cg_key(int fid, int sock)
{
        struct packet data;
        while (true) {
                memset(&data, 0, sizeof(data)); 
                if (!rcv_msg(fid, sock, &data)) {
                        printf("Enc=%d,id=%u,len=%u\n", data.enc, data.id, data.len);
                        if (data.enc) {
                                // Encrypt
                        } else {
                                // Decrypt
                        }
                        memset(data.data, 0, data.len);
                        snd_msg(fid, sock, &data);
                }
        }
}

void cg_main()
{
	int ret, fid, sock;
	struct sockaddr_nl saddr;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		perror("failed to create socket");
		return sock;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	if ((ret=bind(sock, (struct sockaddr *)&saddr, sizeof(saddr))) < 0) {
		perror("failed to bind socket");
		goto err;
	}

	fid = get_fid(sock, "CG");
	if (!fid) {
		printf("failed to get family id\n");
		ret = -1;
		goto err;
	}
	if ((ret=set_pid(sock, fid)) >= 0) {
		cg_key(fid, sock);
	}
err:
	close(sock);
	return ret;
}

int main(int argc, char **argv)
{
	cg_main();
}
