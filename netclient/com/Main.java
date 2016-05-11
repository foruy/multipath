package com;

import com.net.Message;
import com.net.NetClient;
import com.net.NetDevice;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

public class Main {
	public void start(NetClient nc, NetDevice nd) {
		int fd = nc.getFD();

		try {
			Thread.sleep(2);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// Device Sense
                nd.run();

		// Encrypt and Decrypt packet from vxlan
		while (true) {
			Message msg = nc.receive(fd);
			if (msg != null) {
				byte[] data = null;
				byte[] idArr = String.valueOf(msg.id).getBytes();
				byte[] counter = new byte[16];
				System.arraycopy(idArr, 0, counter, 0, idArr.length);

				String clientName = nd.getAddr(msg.sid);
				String serverName = nd.getAddr(msg.did);
				if (clientName == null || "".equals(clientName) ||
						serverName == null || "".equals(serverName))
					continue;

				if (msg.enc) {
					// Encrypt
					data = msg.data;
				} else {
					// Decrypt 
					data = msg.data;
				}

				msg.data = data;
				nc.send(fd, msg);
			}
		}
	}

	public static void main(String[] args) {
		NetDevice nd = new NetDevice();
		nd.checkArgs(args);
		NetClient nc = new NetClient();
		nd.setNC(nc);
		new Main().start(nc, nd);
	}
}
