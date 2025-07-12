package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"os"
	"time"
)

type Service interface {
	GetUsers(ctx context.Context) ([]User, error)
	GetUserById(ctx context.Context, id int) (*User, error)
	UpdateEmail(ctx context.Context, id int, request UpdateEmailRequest) error
	DeleteUser(ctx context.Context, id int) error
	Register(ctx context.Context, request RegisterRequest) (user *User, token string, err error)
	Authenticate(ctx context.Context, request AuthenticationRequest) (token string, err error)
	GenerateJwt(user *User) (string, error)
	ValidateJwt(tokenString string) (*jwt.Token, error)
	GetUserFromValidJwt(ctx context.Context, token *jwt.Token) (*User, error)
}

type ApiService struct {
	store Storage
}

func NewService(storage Storage) *ApiService {
	return &ApiService{store: storage}
}

func (s *ApiService) GetUsers(ctx context.Context) ([]User, error) {
	return s.store.GetUsers(ctx)
}

func (s *ApiService) GetUserById(ctx context.Context, id int) (*User, error) {
	return s.store.GetUserById(ctx, id)
}

func (s *ApiService) UpdateEmail(ctx context.Context, id int, request UpdateEmailRequest) error {
	return s.store.UpdateEmail(ctx, id, request.Email)
}

func (s *ApiService) DeleteUser(ctx context.Context, id int) error {
	return s.store.DeleteUser(ctx, id)
}

func (s *ApiService) Register(ctx context.Context, request RegisterRequest) (user *User, token string, err error) {
	var newUser User
	newUser.Email = request.Email
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}
	newUser.Password = string(hashedPass)
	newUser.CreatedAt = time.Now()
	savedUser, err := s.store.CreateUser(ctx, &newUser)
	if err != nil {
		return nil, "", fmt.Errorf("create new user: %v", err)
	}
	signedKey, err := s.GenerateJwt(savedUser)
	if err != nil {
		return nil, "", fmt.Errorf("create jwt: %v", err)
	}
	return savedUser, signedKey, nil
}

func (s *ApiService) Authenticate(ctx context.Context, request AuthenticationRequest) (token string, err error) {
	user, err := s.store.GetUserByEmail(ctx, request.Email)
	if err != nil {
		return "", fmt.Errorf("no user with email: %s", request.Email)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		return "", fmt.Errorf("invalid password")
	}
	signedJwt, err := s.GenerateJwt(user)
	if err != nil {
		return "", fmt.Errorf("create jwt: %v", err)
	}
	return signedJwt, nil
}

func (s *ApiService) GenerateJwt(user *User) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "getit-api",
		Subject:   user.Email,
		Audience:  []string{"getit-frontend"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        uuid.NewString(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := os.Getenv("JWT_SECRET")
	signedString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return signedString, nil
}

func (s *ApiService) ValidateJwt(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	switch {
	case token.Valid:
		return token, nil
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, fmt.Errorf("malformed token: %v", err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, fmt.Errorf("invalid token signature: %v", err)
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		return nil, fmt.Errorf("token expired or not valid yet: %v", err)
	default:
		return nil, fmt.Errorf("could not handle token: %v", err)
	}
}

func (s *ApiService) GetUserFromValidJwt(ctx context.Context, t *jwt.Token) (*User, error) {
	email, err := t.Claims.GetSubject()
	if err != nil {
		return nil, err
	}
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return user, nil
}
