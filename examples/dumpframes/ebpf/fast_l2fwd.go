package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

//go:generate $HOME/go/bin/bpf2go fast_l2fwd fast_l2fwd.c -- -I/usr/include/ -I./include -nostdinc -O3

type FastL2fwdProgram struct {
	// Program的业务逻辑：把数据报文抓到应用层，应用层根据报文设置 L2fwd map,
	// 这样下次数据到来是，直接在ebpf 根据 L2fwd map信息快速转发, 不需要再把数据拿到应用层了
	Program *ebpf.Program
	//redirect
	RedirectProg *ebpf.Program
	//attach 到出口网卡上。
	DummyProg *ebpf.Program
	//指定处理网卡哪个队列的数据
	Queues *ebpf.Map
	//af_xdp socket 为了把数据包抓到应用层
	Sockets *ebpf.Map

	//fast path, 快速找到目的ip对应转发信息，
	//直接在ebpf处实现修改数据包报文的目的mac并转发到指定的网卡
	L2fwd *ebpf.Map
	//为了实现快速把数据报文转发到指定的网卡
	TxPort *ebpf.Map
}

func NewFastL2fwdProgram(protocol int, options *ebpf.CollectionOptions) (*FastL2fwdProgram, error) {
	spec, err := loadFast_l2fwd()
	if err != nil {
		return nil, err
	}

	if protocol >= 0 && protocol <= 255 {
		if err := spec.RewriteConstants(map[string]interface{}{"PROTO": uint8(protocol)}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("protocol must be between 0 and 255")
	}
	var program fast_l2fwdObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &FastL2fwdProgram{
		Program:      program.XdpSockProg,
		RedirectProg: program.XdpRedirect,
		DummyProg:    program.XdpRedirectDummyProg,
		Queues:       program.QidconfMap,
		Sockets:      program.XsksMap,
		L2fwd:        program.L2fwdMap,
		TxPort:       program.TxportMap,
	}
	return p, nil
}

// Register adds the socket file descriptor as the recipient for packets from the given queueID.
func (p *FastL2fwdProgram) RegisterSocket(queueID int, fd int) error {
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return fmt.Errorf("failed to update xsksMap: %v", err)
	}

	if err := p.Queues.Put(uint32(queueID), uint32(1)); err != nil {
		return fmt.Errorf("failed to update qidconfMap: %v", err)
	}
	return nil
}

// Unregister removes any associated mapping to sockets for the given queueID.
func (p *FastL2fwdProgram) UnregisterSocket(queueID int) error {
	if err := p.Queues.Delete(uint32(queueID)); err != nil {
		return err
	}
	if err := p.Sockets.Delete(uint32(queueID)); err != nil {
		return err
	}
	return nil
}

func (p *FastL2fwdProgram) RegisterL2fwdInfo(dstip net.IP, inif int, outif int, dstMac []byte) error {
	fmt.Printf("------RegisterL2fwdInfo, len(dstMac):%d-------\n", len(dstMac))
	var mac [6]byte
	copy(mac[:], dstMac[:6])
	log.Printf("be ip:%d, le ip:%d", binary.BigEndian.Uint32(dstip), binary.LittleEndian.Uint32(dstip))
	ip := binary.LittleEndian.Uint32(dstip)
	if ip == 0 {
		return errors.New("ip == 0")
	}

	fwd := struct {
		//Outif int
		Outif  uint32
		DstMac [6]byte
	}{uint32(outif), mac}
	log.Printf("need check align is same to bpf; sizeof(fwd):%d\n", unsafe.Sizeof(fwd))

	/* Loading dummy XDP prog on out-device */
	// if err := p.AttachDummyProgram(outif); err != nil {
	// 	return fmt.Errorf("Loading dummy XDP prog on out-device:%d fail, err:%v", outif, err)
	// }
	if err := p.TxPort.Put(uint32(outif), uint32(outif)); err != nil {
		return fmt.Errorf("failed to update TxPort: %v, key=value=%d", err, outif)
	}
	// if err := p.TxPort.Put(uint32(inif), uint32(outif)); err != nil {
	// 	return fmt.Errorf("failed to update TxPort: %v, key=value=%d", err, outif)
	// }

	if err := p.L2fwd.Put(ip, unsafe.Pointer(&fwd)); err != nil {
		return fmt.Errorf("failed to update L2fwd: %v", err)
	}
	return nil
}

// Attach the XDP Program to an interface.
func (p *FastL2fwdProgram) AttachProgram(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.Program)
}

// Detach the XDP Program from an interface.
func (p *FastL2fwdProgram) Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

func Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

// Attach the XDP Redirect Program to an interface.
func (p *FastL2fwdProgram) AttachRedirectProgram(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.RedirectProg)
}

func (p *FastL2fwdProgram) AttachDummyProgram(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.DummyProg)
}

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

// removeProgram removes an existing XDP program from the given network interface.
func removeProgram(Ifindex int) error {
	var link netlink.Link
	var err error
	link, err = netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	if !isXdpAttached(link) {
		return nil
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}
	for {
		link, err = netlink.LinkByIndex(Ifindex)
		if err != nil {
			return err
		}
		if !isXdpAttached(link) {
			break
		}
		time.Sleep(time.Second)
		log.Printf("Ifindex:%d\n", Ifindex)
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}
