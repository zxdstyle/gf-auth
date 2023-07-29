package gfauth

import "errors"

var (
	ErrExpiredToken = errors.New("token is expired")

	ErrInvalidToken = errors.New("token is invalid")

	ErrMissingToken = errors.New("token is required")

	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	ErrForbiddenAbility = errors.New("forbidden")
)
