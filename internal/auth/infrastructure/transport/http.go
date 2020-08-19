package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/jnikolaeva/eshop-common/uuid"

	"github.com/jnikolaeva/authservice/internal/auth/application"
)

const sessionCookieName = "sid"

var (
	ErrUnauthenticated = errors.New("user is not authenticated")
	ErrBadRequest      = errors.New("invalid request")
)

type HttpServer struct {
	errorLogger  log.Logger
	idService    application.IdentityService
	authService  application.AuthService
	sessionStore sessions.Store
}

func NewHttpServer(errorLogger log.Logger, idService application.IdentityService, authService application.AuthService, sessionStore sessions.Store) *HttpServer {
	return &HttpServer{
		errorLogger:  errorLogger,
		idService:    idService,
		authService:  authService,
		sessionStore: sessionStore,
	}
}

func (s *HttpServer) MakeHandler(pathPrefix string) http.Handler {
	r := mux.NewRouter()
	sr := r.PathPrefix(pathPrefix).Subrouter()
	sr.Handle("/register", s.makeRegisterUserHandler()).Methods(http.MethodPost)
	sr.Handle("/{userId}", s.makeDeleteUserHandler()).Methods(http.MethodDelete)
	sr.Handle("/signin", s.makeSignInHandler()).Methods(http.MethodPost)
	sr.Handle("/signin", s.makeSignInPageHandler()).Methods(http.MethodGet)
	sr.Handle("/signout", s.makeSignOutHandler()).Methods(http.MethodPost)
	sr.Handle("/auth", s.makeAuthHandler()).Methods(http.MethodGet)
	return r
}

func (s *HttpServer) makeRegisterUserHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		req, err := decodeRegisterUserRequest(ctx, r)
		if err != nil {
			s.encodeErrorResponse(ctx, err, w)
			return
		}
		userID, err := s.idService.Register(ctx, req.Username, req.Password)
		if err != nil {
			s.encodeErrorResponse(ctx, err, w)
			return
		}
		if err := s.encodeResponse(ctx, w, &registerUserResponse{ID: userID.String()}); err != nil {
			s.encodeErrorResponse(ctx, err, w)
		}
	})
}

func (s *HttpServer) makeDeleteUserHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		vars := mux.Vars(r)
		sID, ok := vars["userId"]
		if !ok {
			s.encodeErrorResponse(ctx, ErrBadRequest, w)
		}
		id, err := uuid.FromString(sID)
		if err != nil {
			s.encodeErrorResponse(ctx, ErrBadRequest, w)
		}
		if err := s.idService.Delete(ctx, id); err != nil {
			s.encodeErrorResponse(ctx, err, w)
		}
		_ = s.encodeResponse(ctx, w, nil)
	})
}

func (s *HttpServer) makeSignInHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		req, err := decodeSignInRequest(ctx, r)
		if err != nil {
			s.encodeErrorResponse(ctx, err, w)
			return
		}
		session, err := s.sessionStore.Get(r, sessionCookieName)
		if err != nil {
			s.encodeErrorResponse(ctx, err, w)
			return
		}

		user, err := s.authService.Login(ctx, req.Username, req.Password)
		if err != nil {
			session.Values["user_id"] = ""
			_ = session.Save(r, w)

			s.encodeErrorResponse(ctx, err, w)
			return
		}

		session.Values["user_id"] = user.ID.String()
		if err = session.Save(r, w); err != nil {
			s.encodeErrorResponse(r.Context(), err, w)
			return
		}

		_ = s.encodeResponse(ctx, w, &signInResponse{
			ID:       user.ID.String(),
			Username: user.Username,
		})
	})
}

func (s *HttpServer) makeSignInPageHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Please use POST request to sign in"))
	})
}

func (s *HttpServer) makeSignOutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionCookieName)
		if err != nil {
			s.encodeErrorResponse(r.Context(), err, w)
			return
		}
		if userID, ok := session.Values["user_id"].(string); !ok || userID == "" {
			// not authenticated
			_ = s.encodeResponse(r.Context(), w, nil)
			return
		}
		session.Values["user_id"] = ""
		if err := session.Save(r, w); err != nil {
			s.encodeErrorResponse(r.Context(), err, w)
			return
		}
		_ = s.encodeResponse(r.Context(), w, nil)
	})
}

func (s *HttpServer) makeAuthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionCookieName)
		if err != nil {
			s.encodeErrorResponse(r.Context(), errors.Wrap(ErrUnauthenticated, err.Error()), w)
			return
		}
		userID, found := session.Values["user_id"]
		if !found || userID == "" {
			s.encodeErrorResponse(r.Context(), ErrUnauthenticated, w)
			return
		}

		w.Header().Set("X-Auth-User-Id", userID.(string))
		w.WriteHeader(http.StatusOK)
	})
}

func decodeRegisterUserRequest(_ context.Context, r *http.Request) (req registerUserRequest, err error) {
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil && e != io.EOF {
		return req, errors.WithMessage(ErrBadRequest, "failed to decode request body")
	}
	if req.Username == "" {
		return req, errors.WithMessage(ErrBadRequest, "missing required field 'username'")
	}
	if req.Password == "" {
		return req, errors.WithMessage(ErrBadRequest, "missing required field 'password'")
	}
	return req, nil
}

func decodeSignInRequest(_ context.Context, r *http.Request) (req signInRequest, err error) {
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil && e != io.EOF {
		return req, errors.WithMessage(ErrBadRequest, "failed to decode request body")
	}
	if req.Username == "" {
		return req, errors.WithMessage(ErrBadRequest, "missing required field 'username'")
	}
	if req.Password == "" {
		return req, errors.WithMessage(ErrBadRequest, "missing required field 'password'")
	}
	return req, nil
}

func (s *HttpServer) encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if response == nil {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func (s *HttpServer) encodeErrorResponse(_ context.Context, err error, w http.ResponseWriter) {
	_ = s.errorLogger.Log("err", fmt.Sprintf("%+v", err))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var errorResponse = translateError(err)
	w.WriteHeader(errorResponse.Status)
	_ = json.NewEncoder(w).Encode(errorResponse.Response)
}

type transportError struct {
	Status   int
	Response errorResponse
}

func translateError(err error) transportError {
	if errors.Is(err, ErrBadRequest) {
		return transportError{
			Status: http.StatusBadRequest,
			Response: errorResponse{
				Code:    103,
				Message: err.Error(),
			},
		}
	} else if errors.Is(err, ErrUnauthenticated) || errors.Is(err, application.ErrUserNotFound) {
		return transportError{
			Status: http.StatusUnauthorized,
			Response: errorResponse{
				Code:    101,
				Message: err.Error(),
			},
		}
	} else if err == application.ErrDuplicateUser {
		return transportError{
			Status: http.StatusConflict,
			Response: errorResponse{
				Code:    102,
				Message: err.Error(),
			},
		}
	} else {
		return transportError{
			Status: http.StatusInternalServerError,
			Response: errorResponse{
				Code:    100,
				Message: "unexpected error",
			},
		}
	}
}
