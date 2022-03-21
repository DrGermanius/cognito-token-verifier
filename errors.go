package cognito_token_verifier

// Error defines string error
type Error string

// Error returns error message
func (e Error) Error() string {
	return string(e)
}

const (
	ErrNoKidHeader   = Error("expecting JWT header to have header kid")
	ErrKidsDontMatch = Error("no matching keyIDs are fetched")
	ErrTokenExpired  = Error("token is expired")
)
