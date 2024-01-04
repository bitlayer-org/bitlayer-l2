package vm

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common"
)

type ActionLogger struct {
	env       *EVM
	callstack []types.ActionFrame
	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

// NewActionLogger returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func NewActionLogger() *ActionLogger {
	// First callframe contains tx context info
	// and is populated on start and end.
	return &ActionLogger{callstack: make([]types.ActionFrame, 1)}
}

func (t *ActionLogger) CaptureTxStart(gasLimit uint64) {}
func (t *ActionLogger) CaptureTxEnd(restGas uint64)    {}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *ActionLogger) CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	t.callstack[0] = types.ActionFrame{
		Action: types.Action{
			OpCode:       "CALL",
			From:         from,
			To:           to,
			Value:        value,
			Depth:        ^uint64(0),
			Gas:          gas,
			Input:        input,
			TraceAddress: nil,
		},
		Calls: nil,
	}
	if create {
		t.callstack[0].OpCode = "CREATE"
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *ActionLogger) CaptureEnd(output []byte, gasUsed uint64, err error) {
	t.callstack[0].GasUsed = gasUsed
	if err != nil {
		t.callstack[0].Error = err.Error()
		if err == ErrExecutionReverted && len(output) > 0 {
			t.callstack[0].Output = output
			reason, errUnpack := abi.UnpackRevert(output)
			if errUnpack == nil {
				t.callstack[0].Error = fmt.Sprintf("execution reverted: %v", reason)
			}
		}
	} else {
		t.callstack[0].Output = output
		t.callstack[0].Success = true
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *ActionLogger) CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error) {
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *ActionLogger) CaptureFault(pc uint64, op OpCode, gas, cost uint64, _ *ScopeContext, depth int, err error) {
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *ActionLogger) CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		t.env.Cancel()
		return
	}

	// length of callstack is equal to call depth
	depth := len(t.callstack) - 1

	// inherit trace address from parent
	parent := t.callstack[depth]
	traceAddr := make([]uint64, len(parent.TraceAddress), len(parent.TraceAddress)+1)
	copy(traceAddr, parent.TraceAddress)

	// get index in its depth
	traceAddr = append(traceAddr, uint64(len(parent.Calls)))

	call := types.ActionFrame{
		Action: types.Action{
			OpCode:       typ.String(),
			From:         from,
			To:           to,
			Value:        value,
			Depth:        uint64(depth),
			Gas:          gas,
			Input:        input,
			TraceAddress: traceAddr,
		},
	}
	t.callstack = append(t.callstack, call)
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *ActionLogger) CaptureExit(output []byte, gasUsed uint64, err error) {
	// current depth
	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.Success = err == nil
	if err == nil {
		call.Output = output
	} else {
		call.Error = err.Error()
		if call.OpCode == "CREATE" || call.OpCode == "CREATE2" {
			call.To = common.Address{}
		}
	}
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *ActionLogger) GetResult() ([]*types.Action, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	actions := make([]*types.Action, 0)
	actions = append(actions, &t.callstack[0].Action)
	// DFS
	var addAction func(actionFrame *types.ActionFrame)
	addAction = func(actionFrame *types.ActionFrame) {
		for i := 0; i < len(actionFrame.Calls); i++ {
			actions = append(actions, &actionFrame.Calls[i].Action)
			addAction(&actionFrame.Calls[i])
		}
	}
	addAction(&t.callstack[0])

	return actions, t.reason
}

func (t *ActionLogger) Clear() {
	t.callstack = make([]types.ActionFrame, 1)
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *ActionLogger) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}
