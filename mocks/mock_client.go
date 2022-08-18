// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/harness/scm/client (interfaces: Client)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	types "github.com/harness/scm/types"
	gomock "github.com/golang/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// Execution mocks base method.
func (m *MockClient) Execution(arg0, arg1 string) (*types.Execution, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Execution", arg0, arg1)
	ret0, _ := ret[0].(*types.Execution)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Execution indicates an expected call of Execution.
func (mr *MockClientMockRecorder) Execution(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Execution", reflect.TypeOf((*MockClient)(nil).Execution), arg0, arg1)
}

// ExecutionCreate mocks base method.
func (m *MockClient) ExecutionCreate(arg0 string, arg1 *types.Execution) (*types.Execution, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecutionCreate", arg0, arg1)
	ret0, _ := ret[0].(*types.Execution)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecutionCreate indicates an expected call of ExecutionCreate.
func (mr *MockClientMockRecorder) ExecutionCreate(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecutionCreate", reflect.TypeOf((*MockClient)(nil).ExecutionCreate), arg0, arg1)
}

// ExecutionDelete mocks base method.
func (m *MockClient) ExecutionDelete(arg0, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecutionDelete", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExecutionDelete indicates an expected call of ExecutionDelete.
func (mr *MockClientMockRecorder) ExecutionDelete(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecutionDelete", reflect.TypeOf((*MockClient)(nil).ExecutionDelete), arg0, arg1)
}

// ExecutionList mocks base method.
func (m *MockClient) ExecutionList(arg0 string, arg1 types.Params) ([]*types.Execution, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecutionList", arg0, arg1)
	ret0, _ := ret[0].([]*types.Execution)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecutionList indicates an expected call of ExecutionList.
func (mr *MockClientMockRecorder) ExecutionList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecutionList", reflect.TypeOf((*MockClient)(nil).ExecutionList), arg0, arg1)
}

// ExecutionUpdate mocks base method.
func (m *MockClient) ExecutionUpdate(arg0, arg1 string, arg2 *types.ExecutionInput) (*types.Execution, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecutionUpdate", arg0, arg1, arg2)
	ret0, _ := ret[0].(*types.Execution)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecutionUpdate indicates an expected call of ExecutionUpdate.
func (mr *MockClientMockRecorder) ExecutionUpdate(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecutionUpdate", reflect.TypeOf((*MockClient)(nil).ExecutionUpdate), arg0, arg1, arg2)
}

// Login mocks base method.
func (m *MockClient) Login(arg0, arg1 string) (*types.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", arg0, arg1)
	ret0, _ := ret[0].(*types.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Login indicates an expected call of Login.
func (mr *MockClientMockRecorder) Login(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockClient)(nil).Login), arg0, arg1)
}

// Pipeline mocks base method.
func (m *MockClient) Pipeline(arg0 string) (*types.Pipeline, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pipeline", arg0)
	ret0, _ := ret[0].(*types.Pipeline)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Pipeline indicates an expected call of Pipeline.
func (mr *MockClientMockRecorder) Pipeline(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pipeline", reflect.TypeOf((*MockClient)(nil).Pipeline), arg0)
}

// PipelineCreate mocks base method.
func (m *MockClient) PipelineCreate(arg0 *types.Pipeline) (*types.Pipeline, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PipelineCreate", arg0)
	ret0, _ := ret[0].(*types.Pipeline)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PipelineCreate indicates an expected call of PipelineCreate.
func (mr *MockClientMockRecorder) PipelineCreate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PipelineCreate", reflect.TypeOf((*MockClient)(nil).PipelineCreate), arg0)
}

// PipelineDelete mocks base method.
func (m *MockClient) PipelineDelete(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PipelineDelete", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// PipelineDelete indicates an expected call of PipelineDelete.
func (mr *MockClientMockRecorder) PipelineDelete(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PipelineDelete", reflect.TypeOf((*MockClient)(nil).PipelineDelete), arg0)
}

// PipelineList mocks base method.
func (m *MockClient) PipelineList(arg0 types.Params) ([]*types.Pipeline, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PipelineList", arg0)
	ret0, _ := ret[0].([]*types.Pipeline)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PipelineList indicates an expected call of PipelineList.
func (mr *MockClientMockRecorder) PipelineList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PipelineList", reflect.TypeOf((*MockClient)(nil).PipelineList), arg0)
}

// PipelineUpdate mocks base method.
func (m *MockClient) PipelineUpdate(arg0 string, arg1 *types.PipelineInput) (*types.Pipeline, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PipelineUpdate", arg0, arg1)
	ret0, _ := ret[0].(*types.Pipeline)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PipelineUpdate indicates an expected call of PipelineUpdate.
func (mr *MockClientMockRecorder) PipelineUpdate(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PipelineUpdate", reflect.TypeOf((*MockClient)(nil).PipelineUpdate), arg0, arg1)
}

// Register mocks base method.
func (m *MockClient) Register(arg0, arg1 string) (*types.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", arg0, arg1)
	ret0, _ := ret[0].(*types.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Register indicates an expected call of Register.
func (mr *MockClientMockRecorder) Register(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockClient)(nil).Register), arg0, arg1)
}

// Self mocks base method.
func (m *MockClient) Self() (*types.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Self")
	ret0, _ := ret[0].(*types.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Self indicates an expected call of Self.
func (mr *MockClientMockRecorder) Self() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Self", reflect.TypeOf((*MockClient)(nil).Self))
}

// Token mocks base method.
func (m *MockClient) Token() (*types.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Token")
	ret0, _ := ret[0].(*types.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Token indicates an expected call of Token.
func (mr *MockClientMockRecorder) Token() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Token", reflect.TypeOf((*MockClient)(nil).Token))
}

// User mocks base method.
func (m *MockClient) User(arg0 string) (*types.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "User", arg0)
	ret0, _ := ret[0].(*types.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// User indicates an expected call of User.
func (mr *MockClientMockRecorder) User(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "User", reflect.TypeOf((*MockClient)(nil).User), arg0)
}

// UserCreate mocks base method.
func (m *MockClient) UserCreate(arg0 *types.User) (*types.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserCreate", arg0)
	ret0, _ := ret[0].(*types.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserCreate indicates an expected call of UserCreate.
func (mr *MockClientMockRecorder) UserCreate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserCreate", reflect.TypeOf((*MockClient)(nil).UserCreate), arg0)
}

// UserDelete mocks base method.
func (m *MockClient) UserDelete(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserDelete", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UserDelete indicates an expected call of UserDelete.
func (mr *MockClientMockRecorder) UserDelete(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserDelete", reflect.TypeOf((*MockClient)(nil).UserDelete), arg0)
}

// UserList mocks base method.
func (m *MockClient) UserList(arg0 types.Params) ([]*types.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserList", arg0)
	ret0, _ := ret[0].([]*types.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserList indicates an expected call of UserList.
func (mr *MockClientMockRecorder) UserList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserList", reflect.TypeOf((*MockClient)(nil).UserList), arg0)
}

// UserUpdate mocks base method.
func (m *MockClient) UserUpdate(arg0 string, arg1 *types.UserInput) (*types.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserUpdate", arg0, arg1)
	ret0, _ := ret[0].(*types.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserUpdate indicates an expected call of UserUpdate.
func (mr *MockClientMockRecorder) UserUpdate(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserUpdate", reflect.TypeOf((*MockClient)(nil).UserUpdate), arg0, arg1)
}
