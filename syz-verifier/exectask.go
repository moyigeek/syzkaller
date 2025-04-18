// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/prog"
)

// EnvDescr represents the environment descriptor.
type EnvDescr int64

const (
	AnyEnvironment EnvDescr = iota
	NewEnvironment
	EnvironmentsCount
)

// ExecTask is the atomic analysis entity. Once executed, it could trigger the
// pipeline propagation for the program.
type ExecTask struct {
	CreationTime   time.Time
	Program        *prog.Prog
	ID             int64
	ExecResultChan ExecResultChan

	priority int // The priority of the item in the queue.
	index    int // The index of the item in the heap.
}

// Serialize serializes the ExecTask into a map for transmission or storage.
func (t *ExecTask) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"CreationTime": t.CreationTime.UnixNano(),
		"Program":      t.Program.Serialize(),
		"ID":           t.ID,
	}
}

// DeserializeExecTask deserializes a map into an ExecTask.
func DeserializeExecTask(data map[string]interface{}, progDeserializer func([]byte) *prog.Prog) *ExecTask {
	return &ExecTask{
		CreationTime: time.Unix(0, int64(data["CreationTime"].(float64))),
		Program:      progDeserializer(data["Program"].([]byte)),
		ID:           int64(data["ID"].(float64)),
	}
}

// ExecTaskFactory is responsible for creating and managing ExecTasks.
type ExecTaskFactory struct {
	chanMapMutex           sync.Mutex
	taskIDToExecResultChan map[int64]ExecResultChan
	taskCounter            int64
}

// MakeExecTaskFactory creates a new ExecTaskFactory.
func MakeExecTaskFactory() *ExecTaskFactory {
	return &ExecTaskFactory{
		taskIDToExecResultChan: make(map[int64]ExecResultChan),
		taskCounter:            -1,
	}
}

// ExecResultChan is a channel for receiving ExecResults.
type ExecResultChan chan *ExecResult

// MakeExecTask creates a new ExecTask.
func (factory *ExecTaskFactory) MakeExecTask(prog *prog.Prog) *ExecTask {
	task := &ExecTask{
		CreationTime:   time.Now(),
		Program:        prog,
		ExecResultChan: make(ExecResultChan),
		ID:             atomic.AddInt64(&factory.taskCounter, 1),
	}

	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	factory.taskIDToExecResultChan[task.ID] = task.ExecResultChan

	return task
}

// ExecTasksQueued returns the number of queued ExecTasks.
func (factory *ExecTaskFactory) ExecTasksQueued() int {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	return len(factory.taskIDToExecResultChan)
}

// DeleteExecTask removes an ExecTask from the factory.
func (factory *ExecTaskFactory) DeleteExecTask(task *ExecTask) {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	delete(factory.taskIDToExecResultChan, task.ID)
}

// GetExecResultChan retrieves the ExecResultChan for a given task ID.
func (factory *ExecTaskFactory) GetExecResultChan(taskID int64) ExecResultChan {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	return factory.taskIDToExecResultChan[taskID]
}

// ExecTaskQueue is a thread-safe priority queue for ExecTasks.
type ExecTaskQueue struct {
	pq ExecTaskPriorityQueue
	mu sync.Mutex
}

// MakeExecTaskQueue creates a new ExecTaskQueue.
func MakeExecTaskQueue() *ExecTaskQueue {
	return &ExecTaskQueue{
		pq: make(ExecTaskPriorityQueue, 0),
	}
}

// PopTask removes and returns the highest-priority task from the queue.
func (q *ExecTaskQueue) PopTask() (*ExecTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pq.Len() == 0 {
		return nil, false
	}
	return heap.Pop(&q.pq).(*ExecTask), true
}

// PushTask adds a task to the queue.
func (q *ExecTaskQueue) PushTask(task *ExecTask) {
	q.mu.Lock()
	defer q.mu.Unlock()
	heap.Push(&q.pq, task)
}

// Len returns the number of tasks in the queue.
func (q *ExecTaskQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pq.Len()
}

// ExecTaskPriorityQueue is a priority queue for ExecTasks.
type ExecTaskPriorityQueue []*ExecTask

func (pq ExecTaskPriorityQueue) Len() int { return len(pq) }

func (pq ExecTaskPriorityQueue) Less(i, j int) bool {
	return pq[i].priority > pq[j].priority
}

func (pq ExecTaskPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *ExecTaskPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*ExecTask)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *ExecTaskPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}
func (t *ExecTask) ToRPC() map[string]interface{} {
	return t.Serialize()
}
