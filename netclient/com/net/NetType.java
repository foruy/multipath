package com.net;

public class NetType {

	public static final int CONST_ADDRESS = 0;
	public static final int CONST_VALID = 1;
	public static final int CONST_RATIO = 2;

	public int id;
	public int idx;
	public String addr;
	public int ratio;
	public boolean local;
	public boolean valid;

	public NetType(int id, int idx) {
		this.id = id;
		this.idx = idx;
		this.addr = "";
		this.ratio = 1;
		this.local = false;
		this.valid = false;
	}
}
