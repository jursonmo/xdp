
#### 查看bpf_printk 打印的信息
1. 它是一个流，会不停读取信息
cat /sys/kernel/debug/tracing/trace_pipe
2. 另一个种等价方式
tail -f /sys/kernel/debug/tracing/trace

```
root@ubuntu:~/xdp/examples/fast_l2fwd# ip link show dev veth0
5: veth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 3a:06:ea:65:63:12 brd ff:ff:ff:ff:ff:ff link-netns net1
    prog/xdp id 35 tag 8eccf137f45dcf88 jited
root@ubuntu:~/xdp/examples/fast_l2fwd# bpftool map
59: array  name qidconf_map  flags 0x0
	key 4B  value 4B  max_entries 64  memlock 4096B
60: hash  name l2fwd_map  flags 0x0
	key 4B  value 12B  max_entries 64  memlock 8192B
61: devmap  name txport_map  flags 0x80
	key 4B  value 4B  max_entries 64  memlock 4096B
63: array  name .rodata  flags 0x80
	key 4B  value 1B  max_entries 1  memlock 4096B
	btf_id 16  frozen
64: xskmap  name xsks_map  flags 0x0
	key 4B  value 4B  max_entries 64  memlock 4096B
root@ubuntu:~/xdp/examples/fast_l2fwd#

root@ubuntu:~# bpftool map dump id 60
key: c0 a8 00 01  value: 07 00 00 00 00 00 00 00  00 00 11 22
Found 1 element
```
发现l2fwd_map 的value 的布局不是我想要的，明显少 33 44, 总大小是12字节 ， 也就是应用层设置l2fwd_map 时，value 的内存布局不对，
应该是07 00 00 00 00 00 11 22 33 44
```go
	fwd := struct {
		Outif int
		DstMac [6]byte
	}
```
    这个fwd 的unsafe.Sizeof(fwd) = 16,  Outif int 被当成8字节对齐了，修改下:
```go
	fwd := struct {
		Outif uint32
		DstMac [6]byte
	}
```
这个fwd 的unsafe.Sizeof(fwd) = 12 , 这下的大小对上了。再查看一下l2fwd_map的内容
```
root@ubuntu:~# bpftool map dump id 84
key: c0 a8 00 01  value: 07 00 00 00 00 00 11 22  33 44 00 00
```
outif :07 00 00 00  mac:00 00 11 22 33 44,  由于是四字节对齐，补两个字节 00 00

#### txport_map: id 101,大小64， 只有一个element ,key:07 value:07
```
root@ubuntu:~# bpftool map
99: array  name qidconf_map  flags 0x0
	key 4B  value 4B  max_entries 64  memlock 4096B
100: hash  name l2fwd_map  flags 0x0
	key 4B  value 12B  max_entries 64  memlock 8192B
101: devmap  name txport_map  flags 0x80
	key 4B  value 4B  max_entries 64  memlock 4096B
103: array  name .rodata  flags 0x80
	key 4B  value 1B  max_entries 1  memlock 4096B
	btf_id 26  frozen
104: xskmap  name xsks_map  flags 0x0
	key 4B  value 4B  max_entries 64  memlock 4096B

//# -p/--pretty：人类友好格式打印, 比如
//$ sudo bpftool -p map show id 13
<!-- {
    "id": 13,
    "type": "sockhash",
    "name": "sock_ops_map",
    "flags": 0,
    "bytes_key": 24,
    "bytes_value": 4,
    "max_entries": 65535,
    "bytes_memlock": 5767168,
    "frozen": 0
} -->

root@ubuntu:~# bpftool map dump id 101
key: 00 00 00 00  value: <no entry>
key: 01 00 00 00  value: <no entry>
key: 02 00 00 00  value: <no entry>
key: 03 00 00 00  value: <no entry>
key: 04 00 00 00  value: <no entry>
key: 05 00 00 00  value: <no entry>
key: 06 00 00 00  value: <no entry>
key: 07 00 00 00  value: 07 00 00 00
.........
key: 3e 00 00 00  value: <no entry>
key: 3f 00 00 00  value: <no entry>
Found 1 element
```

#### tcpdump packet drop by interface

1. https://unix.stackexchange.com/questions/177739/why-are-tcpdump-packets-being-dropped-by-interface
	 * To fill in ps_ifdrop, we parse
	 * /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors

```
ifconfig 也能看出来rx drop
```
 ```
  root@ubuntu:/sys/class/net/veth3/statistics# cat rx_dropped
	247
```
  或者用 ip -s -s link show dev veth3
  ```
  6: veth3@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 1e:5f:69:83:08:a3 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    RX: bytes  packets  errors  dropped overrun mcast
    1076       14       0       247     0       0
    RX errors: length   crc     frame   fifo    missed
               0        0       0       0       0
    TX: bytes  packets  errors  dropped carrier collsns
    1076       14       0       0       0       0
    TX errors: aborted  fifo   window heartbeat transns
               0        0       0       0       2
 ```
  发现dropped：247
https://www.kernel.org/doc/html/latest/networking/statistics.html
rx_dropped：
Number of packets received but not processed, e.g. due to lack of resources or unsupported protocol. For hardware interfaces this counter may include packets discarded due to L2 address filtering but should not include packets dropped by the device due to buffer exhaustion which are counted separately in rx_missed_errors (since procfs folds those two counters together).

其他方法：
1. 大端小端的区别
2. 试下实例l2fwd
3. 直接在宿主机里编译生成ebpf

##### 最终解决了veth XdpFlags 改为2, 参考 xconnect 
```go
func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}

// attachProgram attaches the given XDP program to the network interface.
func attachProgram(Ifindex int, program *ebpf.Program) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	//return netlink.LinkSetXdpFdWithFlags(link, program.FD(), int(xdp.DefaultXdpFlags))
	return netlink.LinkSetXdpFdWithFlags(link, program.FD(), xdpFlags((link).Type()))
}
```
XdpFlags 的定义：https://elixir.bootlin.com/linux/v5.4.170/source/include/uapi/linux/if_link.h#L950

```c
#define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0)
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#define XDP_FLAGS_DRV_MODE		(1U << 2)
#define XDP_FLAGS_HW_MODE		(1U << 3)
#define XDP_FLAGS_MODES			(XDP_FLAGS_SKB_MODE | \
					 XDP_FLAGS_DRV_MODE | \
					 XDP_FLAGS_HW_MODE)
```					 
XDP_FLAGS_SKB_MODE flag, 在网卡上显示 xdpgeneric
```
root@ubuntu:~# ip link show dev veth0
29: veth0@if28: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 6e:f3:43:e8:ca:9d brd ff:ff:ff:ff:ff:ff link-netns net1
    prog/xdp id 18 tag 45631072cbc131ed jited
root@ubuntu:~#
```