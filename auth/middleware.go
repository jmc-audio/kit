package auth

import (
	"github.com/go-kit/kit/endpoint"
	"golang.org/x/net/context"
)

const auth_ctx_key = "AUTH_UUID"

type Authenticator interface {
	Authenticated() endpoint.Middleware
	Authorized() endpoint.Middleware
}

type authenticator struct {
	uuid  string
	authN AuthNFunc
	authZ AuthZFunc
}

func NewAuthenticator(uuid string, authN AuthNFunc, authZ AuthZFunc) Authenticator {
	return &authenticator{uuid: auth_ctx_key + "_" + uuid, authN: authN, authZ: authZ}
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
					return next(context.WithValue(ctx, a.uuid, p), i)
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
			if p, ok = ctx.Value(a.uuid).(Principal); !ok {
				return nil, &UnknownPrincipal{}
			}
			if s, ok = i.(Subject); ok {
				if s == nil {
					return nil, &UnknownSubject{}
				}
				if a.authZ(p, s) {
					return next(ctx, i)
				}
				return nil, &Unauthorized{}
			}
			return func(ctx context.Context, i interface{}) (interface{}, error) {
				return nil, &UnknownSubject{}
			}(ctx, i)
		}
	}
}
