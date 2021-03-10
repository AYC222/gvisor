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

package icmp_bind_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	ipv4Loopback = tcpip.Address("\x7f\x00\x00\x01")

	// Even though ICMP allows larger datagrams we don't test it here as they
	// need to be fragmented and written out as individual frames.
	maxPayloadSize = 1 << 10
)

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

type testResult uint8

type testCase struct {
	bindTo net.IP
	sendTo net.IP
	// sendToBroadcast defines if the socket should have the SO_BROADCAST socket
	// option set to true.
	sendToBroadcast bool
	// bindToDevice defines if the socket should have the SO_BINDTODEVICE socket
	// option equal to the DUT's test interface.
	bindToDevice bool
	// expectData defines if the test runner should receive a packet.
	expectData bool
}

func TestICMPSocketBind(t *testing.T) {
	dut := testbench.NewDUT(t)

	tests := map[string]struct {
		bindTo        net.IP
		expectFailure bool
	}{
		"IPv4Zero": {
			bindTo:        net.IPv4zero,
			expectFailure: false,
		},
		"IPv4Loopback": {
			bindTo:        net.IPv4(127, 0, 0, 1),
			expectFailure: false,
		},
		"IPv4Unicast": {
			bindTo:        dut.Net.RemoteIPv4,
			expectFailure: false,
		},
		"IPv4UnknownUnicast": {
			bindTo:        dut.Net.LocalIPv4,
			expectFailure: true,
		},
		"IPv4MulticastAllSys": {
			bindTo:        net.IPv4allsys,
			expectFailure: true,
		},
		// TODO(gvisor.dev/issue/5711): Uncomment the test cases below once ICMP
		// sockets are no longer allowed to bind to broadcast addresses.
		//
		// "IPv4Broadcast": {
		//		bindTo:        net.IPv4bcast,
		// 		expectFailure: true,
		// },
		// "IPv4SubnetBroadcast": {
		// 		bindTo:        subnetBcast,
		// 		expectFailure: true,
		// },
		"IPv6Zero": {
			bindTo:        net.IPv6zero,
			expectFailure: false,
		},
		"IPv6Unicast": {
			bindTo:        dut.Net.RemoteIPv6,
			expectFailure: false,
		},
		"IPv6UnknownUnicast": {
			bindTo:        dut.Net.LocalIPv6,
			expectFailure: true,
		},
		"IPv6MulticastInterfaceLocalAllNodes": {
			bindTo:        net.IPv6interfacelocalallnodes,
			expectFailure: true,
		},
		"IPv6MulticastLinkLocalAllNodes": {
			bindTo:        net.IPv6linklocalallnodes,
			expectFailure: true,
		},
		"IPv6MulticastLinkLocalAllRouters": {
			bindTo:        net.IPv6linklocalallrouters,
			expectFailure: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var socketFD int32
			var sockaddr unix.Sockaddr

			if test.bindTo.To4() != nil {
				socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
				bindTo := unix.SockaddrInet4{}
				copy(bindTo.Addr[:], test.bindTo.To4())
				sockaddr = &bindTo
			} else {
				socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
				bindTo := unix.SockaddrInet6{
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(bindTo.Addr[:], test.bindTo.To16())
				sockaddr = &bindTo
			}

			ctx := context.Background()
			ret, err := dut.BindWithErrno(ctx, t, socketFD, sockaddr)

			if !test.expectFailure && ret != 0 {
				t.Fatalf("unexpected dut.BindWithErrno error: %v", err)
			}
			if test.expectFailure && ret == 0 {
				t.Fatalf("expected dut.BindWithErrno error")
			}
		})
	}
}
