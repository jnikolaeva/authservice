package application

import (
	"context"

	"github.com/pkg/errors"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type AuthService interface {
	Login(ctx context.Context, username, password string) (*User, error)
}

func NewAuthService(repo Repository) AuthService {
	return &authService{
		repo: repo,
	}
}

type authService struct {
	repo Repository
}

func (s authService) Login(ctx context.Context, username, password string) (*User, error) {
	user, err := s.repo.FindByCredentials(username, password)
	if err != nil {
		return nil, err
	}
	return user, nil
}
