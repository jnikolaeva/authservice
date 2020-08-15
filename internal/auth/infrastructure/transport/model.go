package transport

type registerUserRequest struct {
	credentials
}

type registerUserResponse struct {
	ID string `json:"id"`
}

type signInRequest struct {
	credentials
}

type signInResponse struct {
	ID       string
	Username string
}

type errorResponse struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
