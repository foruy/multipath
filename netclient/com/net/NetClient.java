package com.net;

public class NetClient {

	static {
		System.load("/root/tvx/com/net/libnetclient.so");
	}

	private static int fd;

	public static native int open();
	public static native int reset(int fd);
	public static native int setnum(int fd, int num);
	public static native Message receive(int fd);
	public static native void send(int fd, Message out);
	public static native int set(int fd, int type, NetType nType);
	public static native void close(int fd);

	public NetClient() {
		fd = open();
	}

	public int getFD() {
                if (fd < 0) {
                        System.out.println("Please load vxlan module.");
                        System.exit(-1);
                }

		if (reset(fd) < 0)
			System.exit(-1);

		return fd;
	}

	public int setDev(int num) {
		return setnum(fd, num);
	}

	public int setAddr(int id, int idx, boolean local, String addr) {
		NetType nType = new NetType(id, idx);
		nType.local = local;
		nType.addr = addr;
		return set(fd, nType.CONST_ADDRESS, nType);
	}

	public int setValid(int id, int idx, boolean valid) {
		NetType nType = new NetType(id, idx);
		nType.local = false;
		nType.valid = valid;
		return set(fd, nType.CONST_VALID, nType);
	}

	public int setRatio(int id, int idx, int ratio) {
		NetType nType = new NetType(id, idx);
		nType.local = true;
		nType.ratio = ratio;
		return set(fd, nType.CONST_RATIO, nType);
	}

	protected void finalize() {
		if (fd > 0)
			close(fd);
	}
}
