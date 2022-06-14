package repository

import (
  "context"
  "fmt"
)

type User struct {
  Id int `json:"id" db:"id"`
  Login string `json:"login" db:"login"`
  Email string `json:"email" db:"email"`
  HashedPassword string `json:"hashed_password" db:"hashed_password"`
  CourseId string `json:"course_id" db:"course_id"`
  Name  string `json:"name" db:"name"`
  Surname string `json:"surname" db:"surname"`
}

func (r *Repository) AddNewUser(ctx context.Context, login, email, hashedPassword, name, surname string) (err error) {
  _, err = r.pool.Exec(ctx, `insert into users (login, email, hashed_password, name, surname) values ($1, $2, $3, $4, $5)`, login, email, hashedPassword, name, surname)
	if err != nil {
		err = fmt.Errorf("failed to exec data: %w", err)
		return
	}
	return
}

func (r *Repository) Login(ctx context.Context, login, hashedPassword string) (u User, err error) {
	row := r.pool.QueryRow(ctx, `select id, login, email from users where login = $1 AND hashed_password = $2`, login, hashedPassword)
	if err != nil {
		err = fmt.Errorf("failed to query data: %w", err)
		return
	}
	err = row.Scan(&u.Id, &u.Login, &u.Email)
	if err != nil {
		err = fmt.Errorf("failed to query data: %w", err)
		return
	}
	return
}
