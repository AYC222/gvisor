// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Generic send and receive tests for datagram sockets: UDP, ICMPv4, and ICMPv6.
package generic_dgram_socket_send_recv_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// Even though ICMP allows larger datagrams we don't test it here as they
	// need to be fragmented and written out as individual frames.
	maxPayloadSize = 1 << 10
)

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

type testCase struct {
	bindTo       net.IP
	sendTo       net.IP
	bindToDevice bool
}

func (test testCase) expectedEthLayer(t *testing.T, dut testbench.DUT, socketFD int32) testbench.Layer {
	t.Helper()
	var dst *tcpip.LinkAddress
	if isBroadcast(dut, test.sendTo) {
		dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

		// When sending to broadcast (subnet or limited), the expected ethernet
		// address is also broadcast.
		dst = testbench.LinkAddress(header.EthernetBroadcastAddress)
	} else if test.sendTo.IsMulticast() {
		if sendToV4 := test.sendTo.To4(); sendToV4 != nil {
			dst = testbench.LinkAddress(header.EthernetAddressFromMulticastIPv4Address(tcpip.Address(sendToV4)))
		} else {
			dst = testbench.LinkAddress(header.EthernetAddressFromMulticastIPv6Address(tcpip.Address(test.sendTo.To16())))
		}
	}
	return &testbench.Ether{
		DstAddr: dst,
	}
}

type protocolTest interface {
	Send(t *testing.T, dut testbench.DUT)
	Receive(t *testing.T, dut testbench.DUT)
}

func TestSocket(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcast := subnetBroadcast(dut)

	var tests []protocolTest

	// Test every combination of bound/unbound, broadcast/multicast/unicast
	// bound/destination address, and bound/not-bound to device.
	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv4zero,
		net.IPv4bcast,
		net.IPv4allsys,
		net.IPv6zero,
		subnetBcast,
		dut.Net.RemoteIPv4,
		dut.Net.RemoteIPv6,
	} {
		for _, sendTo := range []net.IP{
			net.IPv4bcast,
			net.IPv4allsys,
			subnetBcast,
			dut.Net.LocalIPv4,
			dut.Net.LocalIPv6,
			dut.Net.RemoteIPv4,
			dut.Net.RemoteIPv6,
		} {
			for _, bindToDevice := range []bool{true, false} {
				test := testCase{
					bindTo:       bindTo,
					sendTo:       sendTo,
					bindToDevice: bindToDevice,
				}
				tests = append(
					tests,
					newICMPv4Test(test),
					newICMPv6Test(test),
					newUDPTest(test),
				)
			}
		}
	}
	t.Run("Send", func(t *testing.T) {
		for _, test := range tests {
			test.Send(t, dut)
		}
	})
	t.Run("Receive", func(t *testing.T) {
		for _, test := range tests {
			test.Receive(t, dut)
		}
	})
}

type icmpV4TestEnv struct {
	socketFD int32
	ident    uint16
	conn     testbench.IPv4Conn
	layers   testbench.Layers
}

type icmpV4Test struct {
	testCase
}

func newICMPv4Test(test testCase) *icmpV4Test {
	return &icmpV4Test{
		testCase: test,
	}
}

func (test *icmpV4Test) setup(t *testing.T, dut testbench.DUT) icmpV4TestEnv {
	t.Helper()

	// Tell the DUT to create a socket.
	var socketFD int32
	var ident uint16

	if test.bindTo != nil {
		socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMP, test.bindTo)
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY.
		socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if test.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
	t.Cleanup(func() {
		conn.Close(t)
	})

	return icmpV4TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			test.expectedEthLayer(t, dut, socketFD),
			&testbench.IPv4{
				DstAddr: testbench.Address(tcpip.Address(test.sendTo.To4())),
			},
		},
	}
}

var _ protocolTest = (*icmpV4Test)(nil)

func (test *icmpV4Test) Send(t *testing.T, dut testbench.DUT) {
	switch {
	case isBroadcastOrMulticast(dut, test.bindTo):
		// ICMP sockets cannot bind to broadcast or multicast addresses.
		return
	case isBroadcastOrMulticast(dut, test.sendTo):
		// TODO(gvisor.dev/issue/5681): Remove this case when ICMP sockets allow
		// sending to broadcast and multicast addresses.
		return
	case test.bindTo.Equal(net.IPv6zero) || test.bindTo.Equal(dut.Net.RemoteIPv6) || test.sendTo.Equal(dut.Net.LocalIPv6):
		// ICMPv4 is not meant for IPv6.
		return
	}

	expectPacket := true
	switch {
	case test.bindTo.Equal(dut.Net.RemoteIPv4) && !isRemoteAddr(dut, test.sendTo):
		// If we're explicitly bound to an interface's unicast address,
		// packets are always sent on that interface.
	case test.bindToDevice && !isRemoteAddr(dut, test.sendTo):
		// If we're explicitly bound to an interface, packets are always
		// sent on that interface.
	case !test.sendTo.Equal(net.IPv4bcast) && !test.sendTo.IsMulticast() && !isRemoteAddr(dut, test.sendTo):
		// If we're not sending to limited broadcast, multicast, or local, the
		// route table will be consulted and packets will be sent on the correct
		// interface.
	default:
		expectPacket = false
	}

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("icmp/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				icmpLayer := &testbench.ICMPv4{
					Type:    testbench.ICMPv4Type(header.ICMPv4Echo),
					Payload: payload,
				}
				bytes, err := icmpLayer.ToBytes()
				if err != nil {
					t.Fatalf("icmpLayer.ToBytes() = %s", err)
				}
				destSockaddr := unix.SockaddrInet4{}
				copy(destSockaddr.Addr[:], test.sendTo.To4())

				// Tell the DUT to send a packet out the ICMP socket.
				if got, want := dut.SendTo(t, env.socketFD, bytes, 0, &destSockaddr), len(bytes); int(got) != want {
					t.Fatalf("got dut.SendTo = %d, want %d", got, want)
				}

				// Verify the test runner received an ICMP packet with the
				// correctly set "ident" header.
				if env.ident != 0 {
					icmpLayer.Ident = &env.ident
				}
				_, err = env.conn.ExpectFrame(t, append(env.layers, icmpLayer), time.Second)
				if expectPacket && err != nil {
					t.Fatal(err)
				}
				if !expectPacket && err == nil {
					t.Fatal("received unexpected packet, socket is not bound to device")
				}
			})
		}
	})
}

func (test *icmpV4Test) Receive(t *testing.T, dut testbench.DUT) {
	switch {
	case isBroadcastOrMulticast(dut, test.bindTo):
		// ICMP sockets cannot bind to broadcast or multicast addresses.
		return
	case test.bindTo.Equal(net.IPv4zero) && isBroadcastOrMulticast(dut, test.sendTo):
		// TODO(gvisor.dev/issue/5763): Remove this if statement once gVisor
		// restricts ICMP sockets to receive only from unicast addresses.
		return
	case test.bindTo.Equal(net.IPv6zero) || test.bindTo.Equal(dut.Net.RemoteIPv6) || test.sendTo.Equal(dut.Net.LocalIPv6):
		// ICMPv4 is not meant for IPv6.
		return
	}

	expectPacket := (test.bindTo.Equal(dut.Net.RemoteIPv4) || test.bindTo.Equal(net.IPv4zero)) && test.sendTo.Equal(dut.Net.RemoteIPv4)

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("icmp/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				icmpLayer := &testbench.ICMPv4{
					Type:    testbench.ICMPv4Type(header.ICMPv4EchoReply),
					Payload: payload,
				}
				if env.ident != 0 {
					icmpLayer.Ident = &env.ident
				}

				// Send an ICMPv4 packet from the test runner to the DUT.
				frame := env.conn.CreateFrame(t, env.layers, icmpLayer)
				env.conn.SendFrame(t, frame)

				// Verify the behavior of the ICMP socket on the DUT.
				if expectPacket {
					payload, err := icmpLayer.ToBytes()
					if err != nil {
						t.Fatalf("icmpLayer.ToBytes() = %s", err)
					}

					// Receive one extra byte to assert the length of the
					// packet received in the case where the packet contains
					// more data than expected.
					len := int32(len(payload)) + 1
					got, want := dut.Recv(t, env.socketFD, len, 0), payload
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
					}
				} else {
					// Expected receive error, set a short receive timeout.
					dut.SetSockOptTimeval(
						t,
						env.socketFD,
						unix.SOL_SOCKET,
						unix.SO_RCVTIMEO,
						&unix.Timeval{
							Sec:  1,
							Usec: 0,
						},
					)
					ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, maxPayloadSize, 0)
					if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
						t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
					}
				}
			})
		}
	})
}

type icmpV6TestEnv struct {
	socketFD int32
	ident    uint16
	conn     testbench.IPv6Conn
	layers   testbench.Layers
}

type icmpV6Test struct {
	testCase
}

func newICMPv6Test(test testCase) *icmpV6Test {
	return &icmpV6Test{
		testCase: test,
	}
}

func (test *icmpV6Test) setup(t *testing.T, dut testbench.DUT) icmpV6TestEnv {
	t.Helper()

	// Tell the DUT to create a socket.
	var socketFD int32
	var ident uint16

	if test.bindTo != nil {
		socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6, test.bindTo)
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if test.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
	t.Cleanup(func() {
		conn.Close(t)
	})

	return icmpV6TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			test.expectedEthLayer(t, dut, socketFD),
			&testbench.IPv6{
				DstAddr: testbench.Address(tcpip.Address(test.sendTo.To16())),
			},
		},
	}
}

var _ protocolTest = (*icmpV6Test)(nil)

func (test *icmpV6Test) Send(t *testing.T, dut testbench.DUT) {
	switch {
	case isBroadcastOrMulticast(dut, test.bindTo):
		// ICMP sockets cannot bind to broadcast or multicast addresses.
		return
	case isBroadcastOrMulticast(dut, test.sendTo):
		// TODO(gvisor.dev/issue/5681): Remove this case when ICMP sockets allow
		// sending to broadcast and multicast addresses.
		return
	case test.bindTo.Equal(net.IPv4zero) || test.bindTo.Equal(dut.Net.RemoteIPv4) || test.sendTo.Equal(dut.Net.LocalIPv4) || test.sendTo.Equal(dut.Net.RemoteIPv4):
		// ICMPv6 is not meant for IPv4.
		return
	}

	expectPacket := test.sendTo.Equal(dut.Net.LocalIPv6)

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("icmpv6/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				icmpLayer := &testbench.ICMPv6{
					Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
					Payload: payload,
				}
				bytes, err := icmpLayer.ToBytes()
				if err != nil {
					t.Fatalf("icmpLayer.ToBytes() = %s", err)
				}
				destSockaddr := unix.SockaddrInet6{
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(destSockaddr.Addr[:], test.sendTo.To16())

				// Tell the DUT to send a packet out the ICMP socket.
				if got, want := dut.SendTo(t, env.socketFD, bytes, 0, &destSockaddr), len(bytes); int(got) != want {
					t.Fatalf("got dut.SendTo = %d, want %d", got, want)
				}

				// Verify the test runner received an ICMP packet with the
				// correctly set "ident" header.
				if env.ident != 0 {
					icmpLayer.Ident = &env.ident
				}
				_, err = env.conn.ExpectFrame(t, append(env.layers, icmpLayer), time.Second)
				if expectPacket && err != nil {
					t.Fatal(err)
				}
				if !expectPacket && err == nil {
					t.Fatal("received unexpected packet, socket is not bound to device")
				}
			})
		}
	})
}

func (test *icmpV6Test) Receive(t *testing.T, dut testbench.DUT) {
	switch {
	case isBroadcastOrMulticast(dut, test.bindTo):
		// ICMP sockets cannot bind to broadcast or multicast addresses.
		return
	case test.bindTo.Equal(net.IPv6zero) && isBroadcastOrMulticast(dut, test.sendTo):
		// TODO(gvisor.dev/issue/5763): Remove this if statement once gVisor
		// restricts ICMP sockets to receive only from unicast addresses.
		return
	case test.bindTo.Equal(net.IPv4zero) || test.bindTo.Equal(dut.Net.RemoteIPv4) || test.sendTo.Equal(dut.Net.LocalIPv4):
		// ICMPv6 is not meant for IPv4.
		return
	}

	expectPacket := true
	switch {
	case test.bindTo.Equal(dut.Net.RemoteIPv6) && test.sendTo.Equal(dut.Net.RemoteIPv6):
	case test.bindTo.Equal(net.IPv6zero) && test.sendTo.Equal(dut.Net.RemoteIPv6):
	case test.bindTo.Equal(net.IPv6zero) && test.sendTo.Equal(net.IPv6linklocalallnodes):
	default:
		expectPacket = false
	}

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("icmpv6/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				icmpLayer := &testbench.ICMPv6{
					Type:    testbench.ICMPv6Type(header.ICMPv6EchoReply),
					Payload: payload,
				}
				if env.ident != 0 {
					icmpLayer.Ident = &env.ident
				}

				// Send an ICMPv6 packet from the test runner to the DUT.
				frame := env.conn.CreateFrame(t, env.layers, icmpLayer)
				env.conn.SendFrame(t, frame)

				// Verify the behavior of the ICMP socket on the DUT.
				if expectPacket {
					payload, err := icmpLayer.ToBytes()
					if err != nil {
						t.Fatalf("icmpLayer.ToBytes() = %s", err)
					}

					// Receive one extra byte to assert the length of the
					// packet received in the case where the packet contains
					// more data than expected.
					len := int32(len(payload)) + 1
					got, want := dut.Recv(t, env.socketFD, len, 0), payload
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
					}
				} else {
					// Expected receive error, set a short receive timeout.
					dut.SetSockOptTimeval(
						t,
						env.socketFD,
						unix.SOL_SOCKET,
						unix.SO_RCVTIMEO,
						&unix.Timeval{
							Sec:  1,
							Usec: 0,
						},
					)
					ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, maxPayloadSize, 0)
					if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
						t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
					}
				}
			})
		}
	})
}

type udpConn interface {
	SrcPort(*testing.T) uint16
	SendFrame(*testing.T, testbench.Layers, ...testbench.Layer)
	ExpectFrame(*testing.T, testbench.Layers, time.Duration) (testbench.Layers, error)
	Close(*testing.T)
}

type udpTestEnv struct {
	socketFD int32
	conn     udpConn
	layers   testbench.Layers
}

type udpTest struct {
	testCase
}

func newUDPTest(tc testCase) *udpTest {
	return &udpTest{
		testCase: tc,
	}
}

func (test *udpTest) setup(t *testing.T, dut testbench.DUT) udpTestEnv {
	t.Helper()

	var (
		socketFD                 int32
		outgoingUDP, incomingUDP testbench.UDP
	)

	// Tell the DUT to create a socket.
	if test.bindTo != nil {
		var remotePort uint16
		socketFD, remotePort = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, test.bindTo)
		outgoingUDP.DstPort = &remotePort
		incomingUDP.SrcPort = &remotePort
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if test.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	var conn udpConn
	var ipLayer testbench.Layer
	if addr := test.sendTo.To4(); addr != nil {
		udpConn := dut.Net.NewUDPIPv4(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv4{
			DstAddr: testbench.Address(tcpip.Address(addr)),
		}
	} else {
		udpConn := dut.Net.NewUDPIPv6(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv6{
			DstAddr: testbench.Address(tcpip.Address(test.sendTo.To16())),
		}
	}
	t.Cleanup(func() {
		conn.Close(t)
	})

	return udpTestEnv{
		socketFD: socketFD,
		conn:     conn,
		layers: testbench.Layers{
			test.expectedEthLayer(t, dut, socketFD),
			ipLayer,
			&incomingUDP,
		},
	}
}

var _ protocolTest = (*udpTest)(nil)

func (test *udpTest) Send(t *testing.T, dut testbench.DUT) {
	if test.bindTo != nil && !sameIPVersion(test.bindTo, test.sendTo) {
		// Cannot send to an IPv4 address from a socket bound to IPv6 (except
		// for IPv4-mapped IPv6), and viceversa.
		return
	}

	expectPacket := !isRemoteAddr(dut, test.sendTo)
	switch {
	case test.bindTo.Equal(dut.Net.RemoteIPv4):
		// If we're explicitly bound to an interface's unicast address,
		// packets are always sent on that interface.
	case test.bindToDevice:
		// If we're explicitly bound to an interface, packets are always
		// sent on that interface.
	case !test.sendTo.Equal(net.IPv4bcast) && !test.sendTo.IsMulticast():
		// If we're not sending to limited broadcast, multicast, or local, the
		// route table will be consulted and packets will be sent on the correct
		// interface.
	default:
		expectPacket = false
	}

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("udp/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				var destSockaddr unix.Sockaddr
				if sendTo4 := test.sendTo.To4(); sendTo4 != nil {
					addr := unix.SockaddrInet4{
						Port: int(env.conn.SrcPort(t)),
					}
					copy(addr.Addr[:], sendTo4)
					destSockaddr = &addr
				} else {
					addr := unix.SockaddrInet6{
						Port:   int(env.conn.SrcPort(t)),
						ZoneId: dut.Net.RemoteDevID,
					}
					copy(addr.Addr[:], test.sendTo.To16())
					destSockaddr = &addr
				}

				// Tell the DUT to send a packet out the UDP socket.
				if got, want := dut.SendTo(t, env.socketFD, payload, 0, destSockaddr), len(payload); int(got) != want {
					t.Fatalf("got dut.SendTo = %d, want %d", got, want)
				}

				// Verify the test runner received a UDP packet with the
				// correct payload.
				layers := append(env.layers, &testbench.Payload{
					Bytes: payload,
				})
				_, err := env.conn.ExpectFrame(t, layers, time.Second)
				if expectPacket && err != nil {
					t.Fatal(err)
				}
				if !expectPacket && err == nil {
					t.Fatal("received unexpected packet, socket is not bound to device")
				}
			})
		}
	})
}

func (test *udpTest) Receive(t *testing.T, dut testbench.DUT) {
	switch {
	case isSubnetBroadcast(dut, test.bindTo) && isBroadcastOrMulticast(dut, test.sendTo):
		// TODO(gvisor.dev/issue/4896): Add bindTo=subnetBcast/sendTo=IPv4bcast
		// and bindTo=subnetBcast/sendTo=IPv4allsys test cases.
		return
	case test.bindTo.Equal(net.IPv6zero) && test.sendTo.Equal(net.IPv4allsys):
		// TODO(gvisor.dev/issue/5956): Remove this if statement once gVisor
		// restricts ICMP sockets to receive only from unicast addresses.
		return
	}

	expectPacket := true
	switch {
	case test.bindTo.Equal(test.sendTo):
	case test.bindTo.Equal(net.IPv4zero) && sameIPVersion(test.bindTo, test.sendTo) && !test.sendTo.Equal(dut.Net.LocalIPv4):
	case test.bindTo.Equal(net.IPv6zero) && isBroadcast(dut, test.sendTo):
	case test.bindTo.Equal(net.IPv6zero) && isRemoteAddr(dut, test.sendTo):
	case isSubnetBroadcast(dut, test.bindTo) && isBroadcastOrMulticast(dut, test.sendTo):
	default:
		expectPacket = false
	}

	boundTestCaseName := "unbound"
	if test.bindTo != nil {
		boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
	}
	name := fmt.Sprintf("udp/%s/sendTo=%s/bindToDevice=%t/expectPacket=%t", boundTestCaseName, test.sendTo, test.bindToDevice, expectPacket)

	t.Run(name, func(t *testing.T) {
		env := test.setup(t, dut)

		for name, payload := range map[string][]byte{
			"empty":    nil,
			"small":    []byte("hello world"),
			"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
		} {
			t.Run(name, func(t *testing.T) {
				// Send a UDP packet from the test runner to the DUT.
				env.conn.SendFrame(t, env.layers, &testbench.Payload{Bytes: payload})

				// Verify the behavior of the ICMP socket on the DUT.
				if expectPacket {
					// Receive one extra byte to assert the length of the
					// packet received in the case where the packet contains
					// more data than expected.
					len := int32(len(payload)) + 1
					got, want := dut.Recv(t, env.socketFD, len, 0), payload
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
					}
				} else {
					// Expected receive error, set a short receive timeout.
					dut.SetSockOptTimeval(
						t,
						env.socketFD,
						unix.SOL_SOCKET,
						unix.SO_RCVTIMEO,
						&unix.Timeval{
							Sec:  1,
							Usec: 0,
						},
					)
					ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, maxPayloadSize, 0)
					if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
						t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
					}
				}
			})
		}
	})
}

func subnetBroadcast(dut testbench.DUT) net.IP {
	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(dut.Net.RemoteIPv4.To4()),
		PrefixLen: dut.Net.IPv4PrefixLength,
	}
	subnet := addr.Subnet()
	return net.IP(subnet.Broadcast())
}

func isSubnetBroadcast(dut testbench.DUT, ip net.IP) bool {
	subnetBcast := subnetBroadcast(dut)
	return ip.Equal(subnetBcast)
}

func isBroadcast(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(net.IPv4bcast) || isSubnetBroadcast(dut, ip)
}

func isBroadcastOrMulticast(dut testbench.DUT, ip net.IP) bool {
	return isBroadcast(dut, ip) || ip.IsMulticast()
}

func sameIPVersion(a, b net.IP) bool {
	return (a.To4() == nil) == (b.To4() == nil)
}

func isRemoteAddr(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(dut.Net.RemoteIPv4) || ip.Equal(dut.Net.RemoteIPv6)
}
