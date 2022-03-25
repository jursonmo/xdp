#### fast_l2fwd 概述
1. 目的是练习， 参考了github.com/asavie/xdp  example 和 github.com/networkop/xdp-xconnect
##### 功能
 1. 第一个功能是快速转发数据：即从指定网卡收到的数据，原封不动转发到指定的出口网卡。
 2. 第二个功能是快速转发数据的同时，根据需求修改指定数据报文的目的mac地址，达到转发到指定后端服务器的作用。
   + 具体实现是 把数据报文抓到应用层，应用层根据报文是否是需要修改的，如果需要修改，那就设置 L2fwd map, 
   + 这样下次数据到来是，直接在ebpf 根据 L2fwd map信息快速转发, 不需要再把数据拿到应用层了
  ```
  比如:
  ./fast_l2fwd -inlink=eth0  -ipproto=1 -dstIp=192.168.0.1  -outlink=eth1 -dstMac=00:00:11:22:33:44
  意思是从eth0 进来的icmp 数据报文，如果目的ip 是192.168.0.1, 那么就转发到eth1, 并且把目的mac 改成00:00:11:22:33:44
  ```
##### 编译
github.com/asavie/xdp 提供了docker 编译的环境，不需要在linux环境下编译，也不需要下载linux 内核源码。
 具体可以查看 github.com/asavie/xdp/examples/dumpframes/ebpf/Makefile
 1. 在github.com/asavie/xdp/examples/dumpframes/ebpf 目录下 执行 make docker
 2. 在github.com/asavie/xdp/examples/dumpframes/ebpf 目录下 执行 make generate, 它会启动一个容器去执行go generate , go generate 就会根据目录下*.go 里generate信息调用bpf2go 生成相关相应的go 代码, 比如fast_l2fwd.go 里的 
   ```go
   //go:generate $HOME/go/bin/bpf2go fast_l2fwd fast_l2fwd.c -- -I/usr/include/ -I./include -nostdinc -O3
   ```

#### 注意事项
https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting#sending-packets-back-to-the-interface-they-came-from
/*
The XDP_TX return value can be used to send the packet back from the same interface it came from. 
This functionality can be used to implement load balancers, to send simple ICMP replies, 
etc. We will use this functionality in the Assignment 1 to implement a simple ICMP echo server.

Note that in order to the transmit and/or redirect functionality to work, 
all involved devices should have an attached XDP program, including both veth peers. 
We have to do this because veth devices won’t deliver redirected/retransmitted XDP frames 
unless there is an XDP program attached to the receiving side of the target veth interface.
Physical hardware will likely behave the same. XDP maintainers are currently working on fixing this behaviour upstream.
See the Veth XDP: XDP for containers talk which describes the reasons behind this problem. 
(The xdpgeneric mode may be used without this limitation.)
*/

xdpgeneric 模式不需要veth peer attached XDP program, fast_l2fwd 就是用xdpgeneric 模式 才测试通过。