package usermangment

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

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
	if err := newUserData.UpdateInfos(db, cookie.Value); err != nil {
		return err
	}
	return nil
}

func (User *User) UpdateInfos(db *sql.DB, cookieValue string) error {
	hashedPassWord, err := bcrypt.GenerateFromPassword([]byte(User.Password), 12)
	if err != nil {
		return errors.New("internal server error")
	}
	res, err := db.Exec("UPDATE users WHERE uuid=? SET username=? email=? password=? VALUES(?, ?, ?, ?)", cookieValue, User.Username, User.Email, hashedPassWord)
	if err != nil {
		return errors.New("cannot change infos")
	}
	if afected, err := res.RowsAffected(); err != nil || afected == 0 {
		return errors.New("account doesn't exist")
	}
	return nil
}
