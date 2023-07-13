package gfauth

import "encoding/json"

type (
	OptionFunc func(opt *Option)

	Option struct {
		Secret        []byte
		ExcludePaths  []string
		Generator     TokenGenerator
		TokenResolver TokenResolver
		JSONEncoder   func(interface{}) ([]byte, error)
		JSONDecoder   func([]byte, interface{}) error
	}
)

func defaultOption() *Option {
	return &Option{
		Generator:     NewHS256JWTGenerator(),
		TokenResolver: ResolveTokenFromHeader,
		JSONEncoder:   json.Marshal,
		JSONDecoder:   json.Unmarshal,
	}
}

func WithExcludePaths(paths ...string) OptionFunc {
	return func(opt *Option) {
		opt.ExcludePaths = append(opt.ExcludePaths, paths...)
	}
}
