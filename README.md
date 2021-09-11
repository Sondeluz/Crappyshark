# Crappyshark

![Crappyshark listening netcat's packets sending a file containing hello's on localhost](https://user-images.githubusercontent.com/56542714/132957590-4a939e47-28c9-4570-82b8-585c08052f6c.gif)


Crappyshark is a simple Linux-only packet sniffer. This has been done for educational purposes, and is loosely based on [this article](https://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/) (though commented...)

It listens to incoming and outgoing packets on all interfaces, and prints header details for Ethernet frames and IP packets. It also prints additional details if the packet happens to be TCP, UDP or ICMP.

# Compiling
Just use `gcc main.c -o crappyshark`

# Running
Run the executable as root (It needs to create a raw socket) without arguments. Optionally pipe the output to a file

