/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2022/5/17
**/
package uprobe_tracing

import (
	"github.com/cilium/ebpf"
	"github.com/ehids/ebpfmanager"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"math"
)

const binaryPath = "/lib/x86_64-linux-gnu/libssl.so"

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:          "uprobe/SSL_write",
			EbpfFuncName:     "probe_entry_SSL_write",
			AttachToFuncName: "SSL_write",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/SSL_write",
			EbpfFuncName:     "probe_ret_SSL_write",
			AttachToFuncName: "SSL_write",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uprobe/SSL_read",
			EbpfFuncName:     "probe_entry_SSL_read",
			AttachToFuncName: "SSL_read",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/SSL_read",
			EbpfFuncName:     "probe_ret_SSL_read",
			AttachToFuncName: "SSL_read",
			BinaryPath:       binaryPath,
		},
	},
	Maps: []*manager.Map{
		{
			Name: "tls_events",
		},
	},
}

func EBPFManager() *manager.Manager {
	return m
}

func EBPFManagerOption(pid int) manager.Options {
	return manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		ConstantEditors: constantEditor(pid),
	}
}

func constantEditor(pid int) []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(pid),
			FailOnMissing: true,
		},
	}

	if pid <= 0 {
		logrus.Printf("target all process. \n")
	} else {
		logrus.Printf("target PID:%d \n", pid)
	}
	return editor
}

