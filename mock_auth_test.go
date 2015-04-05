package authatron

import (
	"github.com/stretchr/testify/mock"
	"net/http"
)

type MockAuthService struct {
	mock.Mock
}

func NewMockAuthService() *MockAuthService {
	return &MockAuthService{}
}

func (ma *MockAuthService) Authenticate(username, password string) (User, error) {
	args := ma.Mock.Called(username, password)
	return args.Get(0).(User), args.Error(1)
}

func (ma *MockAuthService) StoreUserForRequest(w http.ResponseWriter, r *http.Request, user User) error {
	args := ma.Mock.Called(w, r, user)
	return args.Error(0)
}

func (ma *MockAuthService) RetrieveUserFromRequest(r *http.Request) (User, error) {
	args := ma.Mock.Called(r)
	return args.Get(0).(User), args.Error(1)
}

func (ma *MockAuthService) RetrieveUserFromAuthKey(authKey string) (User, error) {
	args := ma.Mock.Called(authKey)
	return args.Get(0).(User), args.Error(1)
}

func (ma *MockAuthService) ForgetUserForRequest(w http.ResponseWriter, r *http.Request) error {
	args := ma.Mock.Called(w, r)
	return args.Error(0)
}
