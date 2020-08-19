package postgres

import (
	"github.com/jackc/pgx"
	"github.com/jnikolaeva/eshop-common/uuid"
	"github.com/pkg/errors"

	"github.com/jnikolaeva/authservice/internal/auth/application"
)

const errUniqueConstraint = "23505"

type rawUser struct {
	ID       string `db:"id"`
	Username string `db:"first_name"`
	Password string `db:"last_name"`
}

type repository struct {
	connPool *pgx.ConnPool
}

func New(connPool *pgx.ConnPool) application.Repository {
	return &repository{
		connPool: connPool,
	}
}

func (r *repository) NextID() application.UserID {
	return application.UserID(uuid.Generate())
}

func (r *repository) Add(user application.User) error {
	_, err := r.connPool.Exec(
		"INSERT INTO users (id, username, password) VALUES ($1, $2, $3)",
		user.ID.String(), user.Username, user.Password)
	return r.convertError(err)
}

func (r *repository) FindByCredentials(username string, password string) (*application.User, error) {
	var raw rawUser
	query := "SELECT id, username, password FROM users WHERE username = $1 AND password = $2"
	err := r.connPool.QueryRow(query, username, password).Scan(&raw.ID, &raw.Username, &raw.Password)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = application.ErrUserNotFound
		}
		return nil, errors.WithStack(err)
	}
	userID, _ := uuid.FromString(raw.ID)
	user := &application.User{
		ID:       application.UserID(userID),
		Username: raw.Username,
		Password: raw.Password,
	}
	return user, nil
}

func (r *repository) Delete(userID application.UserID) error {
	_, err := r.connPool.Exec(
		"DELETE FROM users WHERE id = $1",
		userID.String())
	return r.convertError(err)
}

func (r *repository) convertError(err error) error {
	if err != nil {
		pgErr, ok := err.(pgx.PgError)
		if ok && pgErr.Code == errUniqueConstraint {
			return application.ErrDuplicateUser
		}
		return errors.WithStack(err)
	}
	return nil
}
