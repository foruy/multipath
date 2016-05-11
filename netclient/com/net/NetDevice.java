package com.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;

public class NetDevice {
    private static int id = -1;
    private static final int PORT = 1234;
    private static final int TIMEOUT = 2;
    private DatagramSocket dgs = null;
    private String broadcast;
    private String[] fargs;
    private NetClient nc = null;
    private Map<Integer,Map<Integer,NetTable>> netable = null;
	private Map<Integer,String> pub = new HashMap<Integer,String>();

	public void setNC(NetClient nc) {
		this.nc = nc;
	}

	public String getAddr(int id) {
		return pub.get(id);
	}

    public void bind(String host, int port) throws Exception {
        InetSocketAddress sockAddress = new InetSocketAddress(host, port);
        dgs = new DatagramSocket(sockAddress);
        dgs.setBroadcast(true);
        dgs.setReuseAddress(true);
        System.out.println("Serving UDP Socket on " + host + " port " + port + " ...");
    }

    public final void receive() throws IOException {
        byte[] buffer = new byte[2048];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        dgs.receive(packet);
        ByteArrayInputStream baos = new ByteArrayInputStream(buffer);
        ObjectInputStream ois = new ObjectInputStream(baos);
        try {
            @SuppressWarnings("unchecked")
            Map<Integer,Map<Integer,NetTable>> map = (Map<Integer,Map<Integer,NetTable>>) ois.readObject();
            Iterator<Map.Entry<Integer,Map<Integer,NetTable>>> entries = map.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<Integer,Map<Integer,NetTable>> entry = entries.next();
		String pubAddr = pub.get(entry.getKey());
		if (pubAddr == null || packet.getAddress().getHostAddress().equals(pubAddr)) {
			pub.put(entry.getKey(), packet.getAddress().getHostAddress());
		}
	        if (entry.getKey() == id) continue;
                System.out.println("Packet from>> " + packet.getAddress());
                if (!netable.containsKey(entry.getKey())) {
                    netable.put(entry.getKey(), entry.getValue());
                } else {
                    for (Map.Entry<Integer,NetTable> ntMap : entry.getValue().entrySet()) {
                        update(entry.getKey(), ntMap.getKey(), ntMap.getValue().getAddr());
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void clientSend(String host) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(baos);
            oos.writeObject(netable);
            oos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] buffer = baos.toByteArray();
        try {
            DatagramPacket dgp = new DatagramPacket(buffer, buffer.length,
                             InetAddress.getByName(host), PORT);
            dgs.send(dgp);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public final void close() {
        try {
            dgs.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static Map<String,List<String>> getIPList() {
        Map<String, List<String>> net = new HashMap<String, List<String>>();
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            NetworkInterface networkInterface;
            Enumeration<InetAddress> inetAddresses;
            InetAddress inetAddress;

            while (networkInterfaces.hasMoreElements()) {
                List<String> ipList = new ArrayList<String>();
                networkInterface = networkInterfaces.nextElement();
                inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    inetAddress = inetAddresses.nextElement();
                    if (inetAddress != null && inetAddress instanceof Inet4Address) {
                        ipList.add(inetAddress.getHostAddress());
                    }
                }
                net.put(networkInterface.getName(), ipList);
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }

        return net;
    }

    public void update(int id, int idx, String value) {
        if (idx >= fargs.length) {
            System.out.println("The index '" + idx +"' cannot be bigger than '" + fargs.length + "'");
            return;
        }

        Map<Integer,NetTable> ntMap = netable.get(id);
        if (ntMap != null) {
            NetTable nt = ntMap.get(idx);
            if (nt == null) {
                nt = new NetTable(value, "".equals(value) ? false : true);
            } else if (!value.equals(nt.getAddr())) {
                // update kernel
		boolean local = (id == this.id);
		if (nc.setAddr(id, idx, local, value) == 0)
                nt.setAddr(value);
            }
        }
    }

    protected void ping() {
        for (Map.Entry<Integer,Map<Integer,NetTable>> entries : netable.entrySet()) {
            if (entries.getKey() == id) {
                continue;
            }

            for (Map.Entry<Integer,NetTable> entry : entries.getValue().entrySet()) {
                NetTable nt = entry.getValue();
                if (!"".equals(nt.getAddr())) {
                    boolean stat = false;
                    try {
                        stat = InetAddress.getByName(nt.getAddr()).isReachable(TIMEOUT);
                        System.out.printf("Status>> %s/%s\n", nt.getAddr(), stat ? "Active" : "Down");
                    } catch (UnknownHostException ue) {
                        System.out.printf("unknown host: %s\n", nt.getAddr());
                    } catch (IOException ie) {
                    }

                    if (stat != nt.isValid()) {
                        // update kernel
			if (nc.setValid(entries.getKey(), entry.getKey(), stat) == 0)
                        nt.setValid(stat);
                    }
                }
            }
        }
    }

    public void checkLocal(String[] names, boolean flag) {
        Map<String,List<String>> net = NetDevice.getIPList();
        net.remove("lo");

        if (!flag) {
            for (Map.Entry<Integer,Map<Integer,NetTable>> entry : netable.entrySet())
                System.out.println("Network Table>> " + entry.getKey() + ":" + entry.getValue());
        }
        for (int i=0; i<names.length; i++) {
            String ip = "";
            String name = names[i];
            List<String> ips = net.get(name);
            if (ips == null || ips.size() != 1) {
                if (ips == null)
                    System.out.println("Interface " + name + " does not exists");
                else
                    System.out.println("Interface '" + name + "' must be only one address");

                if (flag) {
                    System.exit(-1);
                }
            } else {
                ip = ips.get(0);
            }
            update(id, i, ip);
        }
    }

    public void checkArgs(String[] args) {
        String appName = NetDevice.class.getName();
        if (args.length < 3) {
            System.out.printf("Usage:  %s <ID> <BCAST> <NIC-NAME>...\n", appName);
            System.out.println("\t<ID>\t\tHost unique number.");
            System.out.println("\t<BCAST>\t\tLocal broadcast address.");
            System.out.println("\t<NIC-NAME>\tMultilink interface.");
            System.out.println("\nExmaple:");
            System.out.printf("\t%s 0 192.168.0.255 eth0 eth1\n", appName);
            System.exit(-1);
        }

        try {
            id = Integer.parseInt(args[0]);
            if (id < 0) throw new NumberFormatException();
        } catch (NumberFormatException ne) {
            System.out.printf("The two parameter '%s' must be valid +number", args[0]);
            System.out.println();
            System.exit(-1);
        }

        broadcast = args[1];
        fargs = Arrays.copyOfRange(args, 2, args.length);
    }

    public void run() {
	if (nc.setDev(fargs.length) < 0) {
		System.out.printf("Failed to call setDev.\n");
		System.exit(-1);
	}

        netable = new HashMap<Integer,Map<Integer,NetTable>>();
        Map<Integer,NetTable> nt = new HashMap<Integer,NetTable>();
        for (int i=0;i<fargs.length;i++) {
            nt.put(i, new NetTable("", true));
        }
        netable.put(id, nt);
        checkLocal(fargs, true);

	try {
		bind("0.0.0.0", PORT);
	} catch (Exception e) {
		close();
		e.printStackTrace();
		System.exit(-1);
	}

        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                clientSend(broadcast);
                checkLocal(fargs, false);
                ping();
            }
        }, 1000, 5000);

	new Thread() {
		@Override
		public void run() {
			while (true) {
				try {
					receive();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}	
		}
	}.start();
    }
}
