package com.net;

import java.io.Serializable;

public class NetTable implements Serializable {
    private static final long serialVersionUID = 1L;

    private String addr;
    private boolean valid;

    public NetTable(String addr, boolean valid) {
        this.addr = addr;
        this.valid = valid;
    }

    public String getAddr() {
        return addr;
    }

    public boolean isValid() {
        return valid;
    }

    public void setAddr(String addr) {
        this.addr= addr;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String toString() {
        return addr;
    }
}
