package application

import (
	"context"
	"errors"

	"github.com/jnikolaeva/eshop-common/uuid"
)

var (
	ErrDuplicateUser = errors.New("user with such username already exists")
)

type IdentityService interface {
	Register(ctx context.Context, username string, password string) (UserID, error)
	Delete(ctx context.Context, userID uuid.UUID) error
}

func NewIdentityService(repo Repository) IdentityService {
	return &service{
		repo: repo,
	}
}

type service struct {
	repo Repository
}

func (s service) Register(ctx context.Context, username string, password string) (UserID, error) {
	user := User{
		ID:       s.repo.NextID(),
		Username: username,
		Password: password,
	}

	if err := s.repo.Add(user); err != nil {
		return user.ID, err
	}

	return user.ID, nil
}

func (s service) Delete(ctx context.Context, userID uuid.UUID) error {
	return s.repo.Delete(UserID(userID))
}
