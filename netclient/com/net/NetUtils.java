package com.net;

import java.net.InetAddress;

public class NetUtils {

    public static long inet_aton(String strIP) throws Exception {
        byte[] bAddr = InetAddress.getByName(strIP).getAddress();
        long netIP = (((long)bAddr[0]) & 0xff) +
                     ((((long)bAddr[1]) & 0xff) << 8) +
                     ((((long)bAddr[2]) & 0xff) << 16) +
                     (((long)bAddr[3] & 0xff) << 24);
        return netIP;
    }

}
