// Code generated by MockGen. DO NOT EDIT.
// Source: core.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	models "github.com/go-park-mail-ru/2023_2_Vkladyshi/pkg/models"
	gomock "github.com/golang/mock/gomock"
)

// MockICore is a mock of ICore interface.
type MockICore struct {
	ctrl     *gomock.Controller
	recorder *MockICoreMockRecorder
}

// MockICoreMockRecorder is the mock recorder for MockICore.
type MockICoreMockRecorder struct {
	mock *MockICore
}

// NewMockICore creates a new mock instance.
func NewMockICore(ctrl *gomock.Controller) *MockICore {
	mock := &MockICore{ctrl: ctrl}
	mock.recorder = &MockICoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockICore) EXPECT() *MockICoreMockRecorder {
	return m.recorder
}

// AddComment mocks base method.
func (m *MockICore) AddComment(filmId, userId uint64, rating uint16, text string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddComment", filmId, userId, rating, text)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddComment indicates an expected call of AddComment.
func (mr *MockICoreMockRecorder) AddComment(filmId, userId, rating, text interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddComment", reflect.TypeOf((*MockICore)(nil).AddComment), filmId, userId, rating, text)
}

// GetFilmComments mocks base method.
func (m *MockICore) GetFilmComments(filmId, first, limit uint64) ([]models.CommentItem, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilmComments", filmId, first, limit)
	ret0, _ := ret[0].([]models.CommentItem)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFilmComments indicates an expected call of GetFilmComments.
func (mr *MockICoreMockRecorder) GetFilmComments(filmId, first, limit interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilmComments", reflect.TypeOf((*MockICore)(nil).GetFilmComments), filmId, first, limit)
}

// GetUserId mocks base method.
func (m *MockICore) GetUserId(ctx context.Context, sid string) (uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserId", ctx, sid)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserId indicates an expected call of GetUserId.
func (mr *MockICoreMockRecorder) GetUserId(ctx, sid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserId", reflect.TypeOf((*MockICore)(nil).GetUserId), ctx, sid)
}