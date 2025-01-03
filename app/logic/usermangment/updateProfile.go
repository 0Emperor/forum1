package usermangment

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func UpdateUserProfile(dataReader io.ReadCloser, req *http.Request) error {
	var newUserData User
	err := json.NewDecoder(dataReader).Decode(&newUserData)
	if err != nil {
		return errors.New("invalid format")
	}
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		return errors.New("internal server error")
	}
	defer db.Close()
	cookie, err := req.Cookie("ticket")
	if err != nil || cookie.Value == "" {
		return errors.New("no cookie")
	}

	if err := newUserData.CheckInfos(db); err != nil {
		return err
	}

	return nil
}

func (User *User) UpdateInfos(db *sql.DB, cookieValue string) error {
	if User.Username != "" {
		_, err := db.Exec("UPDATE users SET username=?,updated_at=? WHERE uuid=? ", User.Username, time.Now().Format(time.DateTime), cookieValue)
		if err != nil {
			return errors.New("internal server error")
		}
	}
	if User.Email != "" {
		_, err := db.Exec("UPDATE users SET email=?, updated_at=? WHERE uuid=? ", User.Email, time.Now().Format(time.DateTime), cookieValue)
		if err != nil {
			return errors.New("internal server error")
		}
	}
	if User.Password != "" {
		hashedPassWord, err := bcrypt.GenerateFromPassword([]byte(User.Password), 12)
		if err != nil {
			return errors.New("internal server error")
		}
		_, err = db.Exec("UPDATE users SET password=?,updated_at=? WHERE uuid=? ", hashedPassWord, time.Now().Format(time.DateTime), cookieValue)
		if err != nil {
			return errors.New("internal server error")
		}
	}

	return nil
}

func (User *User) CheckInfos(db *sql.DB) error {
	var err error
	if User.Username != "" {
		err = ValidUserName(User.Username)
		if err != nil {
			return err
		}
		err = db.QueryRow("SELECT (*) FROM users WHERE username=?", User.Username).Scan()
		if err == nil {
			return errors.New("username taken")
		} else if err != sql.ErrNoRows {
			return errors.New("internal server error")
		}
	}
	if User.Email != "" {
		err = ValidEmail(User.Email)
		if err != nil {
			return err
		}
		err = db.QueryRow("SELECT (*) FROM users WHERE email=?", User.Email).Scan()
		if err == nil {
			return errors.New("email already exists")
		} else if err != sql.ErrNoRows {
			return errors.New("internal server error")
		}
	}
	if User.Password != "" {
		err = ValidPassword(User.Password, User.PasswordConfirm)
		if err != nil {
			return err
		}
	}

	return nil
}
