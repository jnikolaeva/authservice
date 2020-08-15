package application

import "github.com/jnikolaeva/eshop-common/uuid"

type UserID uuid.UUID

func (u UserID) String() string {
	return uuid.UUID(u).String()
}

type User struct {
	ID       UserID
	Username string
	Password string
}

type Repository interface {
	NextID() UserID
	Add(user User) error
	FindByCredentials(username string, password string) (*User, error)
}
