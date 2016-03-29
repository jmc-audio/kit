package auth

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/go-kit/kit/endpoint"
	"golang.org/x/net/context"
)

const auth_ctx_principal = "AUTH_PRINCIPAL"
const auth_ctx_subject = "AUTH_SUBJECT"

type Authenticator interface {
	Authenticated() endpoint.Middleware
	Authorized() endpoint.Middleware
}

type authenticator struct {
	secret string
	authN  AuthNFunc
	authZ  AuthZFunc
}

func NewAuthenticator(secret string, authN AuthNFunc, authZ AuthZFunc) Authenticator {
	return &authenticator{secret: hex.EncodeToString(sha256.New().Sum([]byte(secret))),
		authN: authN,
		authZ: authZ,
	}
}

func (a *authenticator) Authenticated() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, i interface{}) (interface{}, error) {
			var (
				ok bool
				p  Principal
			)

			if p, ok = i.(Principal); ok {
				if a.authN(p) {
					return next(context.WithValue(ctx, auth_ctx_principal, p), i)
				}
				return nil, &Unauthenticated{}
			}
			return func(ctx context.Context, i interface{}) (interface{}, error) {
				return nil, &UnknownPrincipal{}
			}(ctx, i)
		}
	}
}

func (a *authenticator) Authorized() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, i interface{}) (interface{}, error) {
			var (
				ok bool
				s  Subject
				p  Principal
			)
			if p, ok = ctx.Value(auth_ctx_principal).(Principal); !ok {
				return nil, &UnknownPrincipal{}
			}
			if s, ok = i.(Subject); ok {
				if s == nil {
					return nil, &UnknownSubject{}
				}
				if a.authZ(p, s) {
					return next(context.WithValue(ctx, auth_ctx_subject, s), i)
				}
				return nil, &Unauthorized{}
			}
			return func(ctx context.Context, i interface{}) (interface{}, error) {
				return nil, &UnknownSubject{}
			}(ctx, i)
		}
	}
}
