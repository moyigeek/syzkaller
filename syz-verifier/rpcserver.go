// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"net"
	"os"
	"sync"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
)

type SyscallReason struct {
	ID     int
	Reason string
}

// RunnerConnectArgs represents the arguments for the Connect RPC call.
type RunnerConnectArgs struct {
	Pool int
	VM   int
}

// RunnerConnectRes represents the response for the Connect RPC call.
type RunnerConnectRes struct {
	CheckUnsupportedCalls bool
}

// UpdateUnsupportedArgs represents the arguments for the UpdateUnsupported RPC call.
type UpdateUnsupportedArgs struct {
	Pool             int
	UnsupportedCalls []UnsupportedCall
}

// UnsupportedCall represents a system call that is not supported.
type UnsupportedCall struct {
	ID     int
	Reason string
}

// NextExchangeArgs represents the arguments for the NextExchange RPC call.
type NextExchangeArgs struct {
	Pool       int
	VM         int
	ExecTaskID int64
	Hanged     bool
	Info       *ExecInfo
}

// ExecInfo represents execution information sent by the runner.
type ExecInfo struct {
	Calls []int
}

// NextExchangeRes represents the response for the NextExchange RPC call.
type NextExchangeRes struct {
	ExecTask ExecTask
}

// RPCServer is a wrapper around the rpc.Server. It communicates with Runners,
// generates programs and sends complete Results for verification.
type RPCServer struct {
	vrf  *Verifier
	port int

	// protects next variables
	mu sync.Mutex
	// used to count the pools w/o UnsupportedCalls result
	notChecked int
	// vmTasks store the per-VM currently assigned tasks Ids
	vmTasksInProgress map[int]map[int64]bool
}

func startRPCServer(vrf *Verifier) (*RPCServer, error) {
	srv := &RPCServer{
		vrf:        vrf,
		notChecked: len(vrf.pools),
	}

	s, err := rpctype.NewRPCServer(vrf.addr, "Verifier", srv)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	srv.port = s.Addr().(*net.TCPAddr).Port

	go s.Serve()
	return srv, nil
}

// Connect notifies the RPCServer that a new Runner was started.
func (srv *RPCServer) Connect(a *RunnerConnectArgs, r *RunnerConnectRes) error {
	r.CheckUnsupportedCalls = !srv.vrf.pools[a.Pool].checked
	return nil
}

// UpdateUnsupported communicates to the server the list of system calls not
// supported by the kernel corresponding to this pool and updates the list of
// enabled system calls. This function is called once for each kernel.
// When all kernels have reported the list of unsupported system calls, the
// choice table will be created using only the system calls supported by all
// kernels.
func (srv *RPCServer) UpdateUnsupported(a *UpdateUnsupportedArgs, r *int) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.vrf.pools[a.Pool].checked {
		return nil
	}
	srv.vrf.pools[a.Pool].checked = true
	vrf := srv.vrf

	for _, unsupported := range a.UnsupportedCalls {
		if c := vrf.target.Syscalls[unsupported.ID]; vrf.calls[c] {
			vrf.reasons[c] = unsupported.Reason
		}
	}

	srv.notChecked--
	if srv.notChecked == 0 {
		vrf.finalizeCallSet(os.Stdout)

		vrf.stats.SetSyscallMask(vrf.calls)
		vrf.SetPrintStatAtSIGINT()

		vrf.choiceTable = vrf.target.BuildChoiceTable(nil, vrf.calls)
		vrf.progGeneratorInit.Done()
	}
	return nil
}

// NextExchange is called when a Runner requests a new program to execute and,
// potentially, wants to send a new Result to the RPCServer.
func (srv *RPCServer) NextExchange(a *NextExchangeArgs, r *NextExchangeRes) error {
	if a.Info != nil && a.Info.Calls != nil {
		// Convert ExecInfo.Calls (type []int) to []*flatrpc.CallInfoRawT
		var callInfoList []*flatrpc.CallInfoRawT
		for range a.Info.Calls {
			callInfoList = append(callInfoList, &flatrpc.CallInfoRawT{
				Flags:  0,   // Set appropriate flags if needed
				Error:  0,   // Set appropriate error if needed
				Signal: nil, // Set appropriate signal if needed
				Cover:  nil, // Set appropriate cover if needed
				Comps:  nil, // Set appropriate comparisons if needed
			})
		}

		// Create a flatrpc.ProgInfo instance
		progInfo := flatrpc.ProgInfo{
			Calls: callInfoList,
		}

		srv.stopWaitResult(a.Pool, a.VM, a.ExecTaskID)
		srv.vrf.PutExecResult(&ExecResult{
			Pool:       a.Pool,
			Hanged:     a.Hanged,
			Info:       progInfo, // Pass the value, not the pointer
			ExecTaskID: a.ExecTaskID,
		})
	}

	// TODO: NewEnvironment is the currently hardcoded logic. Relax it.
	task := srv.vrf.GetRunnerTask(a.Pool, NewEnvironment)
	srv.startWaitResult(a.Pool, a.VM, task.ID)
	r.ExecTask = *task

	return nil
}
func vmTasksKey(poolID, vmID int) int {
	return poolID*1000 + vmID
}

func (srv *RPCServer) startWaitResult(poolID, vmID int, taskID int64) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.vmTasksInProgress == nil {
		srv.vmTasksInProgress = make(map[int]map[int64]bool)
	}

	if srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] == nil {
		srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] =
			make(map[int64]bool)
	}

	srv.vmTasksInProgress[vmTasksKey(poolID, vmID)][taskID] = true
}

func (srv *RPCServer) stopWaitResult(poolID, vmID int, taskID int64) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.vmTasksInProgress[vmTasksKey(poolID, vmID)], taskID)
}

// cleanup is called when a vm.Instance crashes.
func (srv *RPCServer) cleanup(poolID, vmID int) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// Signal error for every VM related task and let upper level logic to process it.
	for taskID := range srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] {
		srv.vrf.PutExecResult(&ExecResult{
			Pool:       poolID,
			ExecTaskID: taskID,
			Crashed:    true,
			Error:      errors.New("VM crashed during the task execution"),
		})
	}
	delete(srv.vmTasksInProgress, vmTasksKey(poolID, vmID))
}
