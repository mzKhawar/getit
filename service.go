package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type Service interface {
	GetUsers(ctx context.Context) ([]UserResponse, error)
	GetUserById(ctx context.Context, id int) (UserResponse, error)
	UpdateEmail(ctx context.Context, id int, request UpdateEmailRequest) error
	DeleteUser(ctx context.Context, id int) error
	Register(ctx context.Context, request RegisterRequest) (UserResponse, error)
	Authenticate(ctx context.Context, request AuthenticationRequest) (string, error)
}

type ApiService struct {
	store Storage
}

func NewService(storage Storage) *ApiService {
	return &ApiService{store: storage}
}

func (s *ApiService) GetUsers(ctx context.Context) ([]UserResponse, error) {
	users, err := s.store.GetUsers(ctx)
	if err != nil {
		return nil, err
	}
	var usersResponse []UserResponse
	for _, usr := range users {
		usersResponse = append(usersResponse, mapUserToResponse(&usr))
	}
	return usersResponse, nil
}

func (s *ApiService) GetUserById(ctx context.Context, id int) (UserResponse, error) {
	user, err := s.store.GetUserById(ctx, id)
	if err != nil {
		return UserResponse{}, err
	}
	res := mapUserToResponse(user)
	return res, nil
}

func (s *ApiService) UpdateEmail(ctx context.Context, id int, request UpdateEmailRequest) error {
	return s.store.UpdateEmail(ctx, id, request.Email)
}

func (s *ApiService) DeleteUser(ctx context.Context, id int) error {
	return s.store.DeleteUser(ctx, id)
}

func (s *ApiService) Register(ctx context.Context, request RegisterRequest) (UserResponse, error) {
	var usr User
	usr.Email = request.Email
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return UserResponse{}, err
	}
	usr.Password = string(hashedPass)
	usr.CreatedAt = time.Now()
	savedUser, err := s.store.CreateUser(ctx, &usr)
	if err != nil {
		return UserResponse{}, fmt.Errorf("error saving user: %v", err)
	}
	res := mapUserToResponse(savedUser)
	return res, nil
}

func (s *ApiService) Authenticate(ctx context.Context, request AuthenticationRequest) (string, error) {
	user, err := s.store.GetUserByEmail(ctx, request.Email)
	if err != nil {
		return "", fmt.Errorf("no user with email: %s", request.Email)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		return "", fmt.Errorf("invalid password")
	}
	return "jwt", nil
}

func mapUserToResponse(u *User) UserResponse {
	var res UserResponse
	res.Id = u.Id
	res.Email = u.Email
	res.CreatedAt = u.CreatedAt
	return res
}
