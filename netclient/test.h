#ifndef _TEST_H
#define _TEST_H

#include <linux/genetlink.h>

#define MAX_BUF_SIZE 2000

enum {
        CG_ATTR_UNSPEC,
        CG_ATTR_PID,
        CG_ATTR_PACKET,
        __CG_ATTR_MAX,
};

#define CG_ATTR_MAX (__CG_ATTR_MAX - 1)

enum commands {
        CG_CMD_UNSPEC,
        CG_CMD_PID,
        CG_CMD_PACKET,
        __CG_CMD_MAX,
};
#define CG_CMD_MAX (__CG_CMD_MAX - 1)

struct packet {
        u_int32_t id;
        u_int32_t ifindex;
        u_int16_t len;
        bool enc;
        unsigned char data[MAX_BUF_SIZE];
};

#endif
