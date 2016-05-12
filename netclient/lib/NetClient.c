#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "com_net_NetClient.h"

static u_int16_t fid = 0;

static int send_msg(int fd, u_int16_t nlmsg_type, u_int32_t nlmsg_pid,
                    u_int8_t genl_cmd, u_int8_t genl_version, u_int16_t nla_type,
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

static int get_fid(int fd, char *fname)
{
	nlmsg ans;
	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

	rc = send_msg(fd, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, 1, CTRL_ATTR_FAMILY_NAME, (void *)fname, strlen(fname) + 1);
	if (rc < 0)
		goto ret;

	rep_len = recv(fd, &ans, sizeof(ans), 0);
	//if (rep_len < 0 || ans.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&ans.n), rep_len))
	if (rep_len < 0 || ans.n.nlmsg_type == NLMSG_ERROR)
		goto ret;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID)
		id = *(__u16 *) NLA_DATA(na);
ret:
	return id;
}

static int create_sock()
{
	int sock;
	struct sockaddr_nl saddr;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        if (sock < 0) {
                perror("failed to create socket");
                return sock;
        }

        memset(&saddr, 0, sizeof(saddr));
        saddr.nl_family = AF_NETLINK;
        saddr.nl_pid = getpid();
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
                perror("failed to bind socket");
		close(sock);
                return -1;
        }

	fid = get_fid(sock, NAME);
	if (!fid) {
		printf("failed to get family id\n");
		close(sock);
		return -1;
	}

	return sock;

}

static int receive_msg(u_int16_t fid, int sock, struct packet *data)
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

JNIEXPORT jint JNICALL Java_com_net_NetClient_open(JNIEnv *env, jclass obj)
{
	return create_sock();
}

JNIEXPORT jint JNICALL Java_com_net_NetClient_reset(JNIEnv *env, jclass obj, jint jfd)
{
	u_int32_t pid = getpid();
	int ret = send_msg(jfd, fid, pid, CG_CMD_PID, 1, CG_ATTR_PID, (void *) &pid, sizeof(u_int32_t));
	if (ret < 0) {
		printf("failed to set pid\n");
		close(jfd);
	}
	return ret;
}

JNIEXPORT jint JNICALL Java_com_net_NetClient_setnum(JNIEnv *env, jclass obj, jint jfd, jint jnum)
{
	u_int16_t num = jnum;
	int ret = send_msg(jfd, fid, getpid(), CG_CMD_PID, 1, CG_ATTR_DEVNUM, (void *) &jnum, sizeof(u_int16_t));
	if (ret < 0) {
		printf("failed to set devnum\n");
		close(jfd);
	}
	return ret;
}

JNIEXPORT jobject JNICALL Java_com_net_NetClient_receive(JNIEnv *env, jclass obj, jint jfd)
{
	struct packet pack;
	if (receive_msg(fid, jfd, &pack)) {
		return NULL;
	}

	jclass mcls = (*env)->FindClass(env, "com/net/Message");
	jfieldID jid = (*env)->GetFieldID(env, mcls, "id", "I");
	jfieldID jifindex = (*env)->GetFieldID(env, mcls, "ifindex", "I");
	jfieldID jlen = (*env)->GetFieldID(env, mcls, "len", "S");
	jfieldID jsid = (*env)->GetFieldID(env, mcls, "sid", "S");
	jfieldID jdid = (*env)->GetFieldID(env, mcls, "did", "S");
	jfieldID jenc = (*env)->GetFieldID(env, mcls, "enc", "Z");
	jfieldID jdata = (*env)->GetFieldID(env, mcls, "data", "[B");

	jobject mobj = (*env)->AllocObject(env, mcls);
	(*env)->SetIntField(env, mobj, jid, pack.id);
	(*env)->SetIntField(env, mobj, jifindex, pack.ifindex);
	(*env)->SetShortField(env, mobj, jlen, pack.len);
	(*env)->SetShortField(env, mobj, jsid, pack.sid);
	(*env)->SetShortField(env, mobj, jdid, pack.did);
	(*env)->SetBooleanField(env, mobj, jenc, pack.enc);
	jbyteArray jarr = (*env)->NewByteArray(env, pack.len);
	(*env)->SetByteArrayRegion(env, jarr, 0, pack.len, pack.data);
	(*env)->SetObjectField(env, mobj, jdata, jarr);

	return mobj;
}

JNIEXPORT void JNICALL Java_com_net_NetClient_send(JNIEnv *env, jclass obj, jint jfd, jobject jmsg)
{
	jclass mcls = (*env)->GetObjectClass(env, jmsg);
	jfieldID jid = (*env)->GetFieldID(env, mcls, "id", "I");
	jfieldID jifindex = (*env)->GetFieldID(env, mcls, "ifindex", "I");
	jfieldID jlen = (*env)->GetFieldID(env, mcls, "len", "S");
	jfieldID jsid = (*env)->GetFieldID(env, mcls, "sid", "S");
	jfieldID jdid = (*env)->GetFieldID(env, mcls, "did", "S");
	jfieldID jenc = (*env)->GetFieldID(env, mcls, "enc", "Z");
	jfieldID jdata = (*env)->GetFieldID(env, mcls, "data", "[B");

	struct packet pack;
	memset(&pack, 0, sizeof(struct packet));
	pack.id = (*env)->GetIntField(env, jmsg, jid);
	pack.ifindex = (*env)->GetIntField(env, jmsg, jifindex);
	pack.len = (*env)->GetShortField(env, jmsg, jlen);
	pack.sid = (*env)->GetShortField(env, jmsg, jsid);
	pack.did = (*env)->GetShortField(env, jmsg, jdid);
	pack.enc = (*env)->GetBooleanField(env, jmsg, jenc);
	jbyteArray data = (*env)->GetObjectField(env, jmsg, jdata);
	//pack.data = (*env)->GetByteArrayElements(env, data, JNI_FALSE);
	memcpy(pack.data, (*env)->GetByteArrayElements(env, data, JNI_FALSE), pack.len);

	send_msg(jfd, fid, getpid(), CG_CMD_PACKET, 1, CG_ATTR_PACKET, (void *) &pack, sizeof(struct packet));

	//(*env)->ReleaseByteArrayElements(env, data, pack.data, JNI_ABORT);
}

JNIEXPORT jint JNICALL Java_com_net_NetClient_set
  (JNIEnv *env, jclass obj, jint jfd, jint type, jobject jtype)
{
	enum attrs atype;

	switch (type) {
	case 0:
		atype = CG_ATTR_ADDR;
		break;
	case 1:
		atype = CG_ATTR_VALID;
		break;
	case 2:
		atype = CG_ATTR_RATIO;
		break;
	default:
		return -1;
	}

	jclass tcls = (*env)->GetObjectClass(env, jtype);
	jfieldID jid = (*env)->GetFieldID(env, tcls, "id", "I");
	jfieldID jidx = (*env)->GetFieldID(env, tcls, "idx", "I");
	jfieldID jaddr = (*env)->GetFieldID(env, tcls, "addr", "Ljava/lang/String;");
	jfieldID jratio = (*env)->GetFieldID(env, tcls, "ratio", "I");
	jfieldID jlocal = (*env)->GetFieldID(env, tcls, "local", "Z");
	jfieldID jvalid = (*env)->GetFieldID(env, tcls, "valid", "Z");

	struct netable nt;
	memset(&nt, 0, sizeof(struct netable));
	nt.id = (*env)->GetIntField(env, jtype, jid);
	nt.idx = (*env)->GetIntField(env, jtype, jidx);
	nt.ratio = (*env)->GetIntField(env, jtype, jratio);
	nt.local = (*env)->GetBooleanField(env, jtype, jlocal);
	nt.valid = (*env)->GetBooleanField(env, jtype, jvalid);

	jstring jstraddr = (*env)->GetObjectField(env, jtype, jaddr);
	const char *addr = (*env)->GetStringUTFChars(env, jstraddr, 0);
	struct in_addr sin_addr;

	if (strlen(addr)) {
	    if (!inet_aton(addr, &sin_addr)) {
		perror("failed to run inet_aton");
		return -1;
	    }
	} else {
		sin_addr.s_addr = 0;
	}
	(*env)->ReleaseStringUTFChars(env, jstraddr, addr);

	nt.addr = sin_addr.s_addr;

	return send_msg(jfd, fid, getpid(), CG_CMD_PACKET, 1, atype, (void *) &nt, sizeof(struct netable));
}

JNIEXPORT void JNICALL Java_com_net_NetClient_close(JNIEnv *env, jclass obj, jint jfd)
{
	if (jfd > 0) close(jfd);
}
