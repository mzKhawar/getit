package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
)

type Storage interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUsers(ctx context.Context) ([]User, error)
	GetUserById(ctx context.Context, id int) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateEmail(ctx context.Context, id int, email string) error
	DeleteUser(ctx context.Context, id int) error
}

type PostgresStore struct {
	conn *pgx.Conn
}

func NewPostgresStore(ctx context.Context) (*PostgresStore, error) {
	conn, err := pgx.Connect(ctx, os.Getenv("DB_URL"))
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}
	return &PostgresStore{conn: conn}, nil
}

func (p *PostgresStore) Init(ctx context.Context) error {
	return p.CreateUserTable(ctx)
}

func (p *PostgresStore) CreateUserTable(ctx context.Context) error {
	query := `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL
	)`

	_, err := p.conn.Exec(ctx, query)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) CreateUser(ctx context.Context, user *User) (*User, error) {
	var savedUser User
	row := p.conn.QueryRow(ctx, "INSERT INTO users (email, password, created_at) VALUES ($1, $2, $3) RETURNING *", user.Email, user.Password, user.CreatedAt)
	if err := row.Scan(&savedUser.Id, &savedUser.Email, &savedUser.Password, &savedUser.CreatedAt); err != nil {
		return nil, err
	}
	return &savedUser, nil
}

func (p *PostgresStore) GetUsers(ctx context.Context) ([]User, error) {
	rows, err := p.conn.Query(ctx, "SELECT * FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var usr User
		if err := rows.Scan(&usr.Id, &usr.Email, &usr.Password, &usr.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, usr)
	}
	return users, nil
}

func (p *PostgresStore) GetUserById(ctx context.Context, id int) (*User, error) {
	row := p.conn.QueryRow(ctx, "SELECT * FROM users WHERE id = $1", id)
	var usr User
	if err := row.Scan(&usr.Id, &usr.Email, &usr.Password, &usr.CreatedAt); err != nil {
		return nil, err
	}
	return &usr, nil
}

func (p *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := p.conn.QueryRow(ctx, "SELECT * FROM users WHERE email = $1", email)
	var usr User
	if err := row.Scan(&usr.Id, &usr.Email, &usr.Password, &usr.CreatedAt); err != nil {
		return nil, err
	}
	return &usr, nil
}

func (p *PostgresStore) UpdateEmail(ctx context.Context, id int, email string) error {
	_, err := p.conn.Exec(ctx, "UPDATE users SET email = $2 WHERE id = $1", id, email)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) DeleteUser(ctx context.Context, id int) error {
	_, err := p.conn.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}
