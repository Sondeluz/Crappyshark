# Crappyshark

![Crappyshark listening netcat's packets sending a file containing hello's on localhost](https://user-images.githubusercontent.com/56542714/132957498-e7e8c1eb-0102-4571-8888-979b04e2a493.gif)

Crappyshark is a simple Linux packet sniffer. This has been done for educational purposes, and is loosely based on https://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/ (though commented...)

It listens to incoming and outgoing packets on all interfaces, and prints header details for Ethernet frames and IP packets. It also prints additional details if the packet happens to be TCP, UDP or ICMP.

# Compiling
Just use `gcc main.c -o crappyshark`

# Running
Run the executable as root (It needs to create a raw socket) without arguments. Optionally pipe the output to a file

