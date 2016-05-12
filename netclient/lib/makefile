CXX = gcc
JAVA_HOME = /usr/local/jdk1.8.0_72

default:
	gcc -I $(JAVA_HOME)/include/ -I $(JAVA_HOME)/include/linux/ -fPIC -shared -o libnetclient.so NetClient.c

clean:
	rm -rf libnetclient.so
	rm -rf *.o
