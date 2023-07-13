package gfauth

type (
	IUser interface {
		GetIdentifier() string
	}

	IUserWithCustomClaims interface {
		GetCustomClaims() map[string]interface{}
	}
)
