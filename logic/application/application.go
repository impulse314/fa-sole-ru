package application

import (
	"fmt"
	"time"
	"strings"
	"context"
	"errors"
	"crypto/md5"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"github.com/jackc/pgx/pgxpool"
	"github.com/julienschmidt/httprouter"
  "github.com/RamuchiRam/fasole-alpha/logic/repository"
)

type app struct {
	ctx    context.Context
	repo   *repository.Repository
	cache 	map[string]repository.User
}

func (a app) authorized(next httprouter.Handle) httprouter.Handle {
	return func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		token, err := readCookie("token", r)
		if err != nil {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		if _, ok := a.cache[token]; !ok {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}
		next(rw, r, ps)
	}
}

func readCookie(name string, r *http.Request) (value string, err error) {
	if name == "" {
		return value, errors.New("you are trying to read empty cookie")
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return value, err
	}
	str := cookie.Value
	value, _ = url.QueryUnescape(str)
	return value, err
}

func NewApp(ctx context.Context, dbpool *pgxpool.Pool) *app {
	return &app{ctx, repository.NewRepository(dbpool), make(map[string]repository.User)}
}

func (a app) Routes(r *httprouter.Router) {
	r.ServeFiles("/public/*filepath", http.Dir("public"))
	r.GET("/", a.authorized(a.StartPage))
	r.GET("/courses", a.authorized(a.CoursesPage))
	r.GET("/about", a.authorized(a.AboutPage))
	r.GET("/links", a.authorized(a.LinksPage))
	r.GET("/keyscourse", a.authorized(a.KeyscoursePage))
	// <summary> СТРАНИЦЫ ТАБОВ
	r.GET("/tabs", a.authorized(a.MainTabsPage))
	r.GET("/closer", a.authorized(a.TabsCloserPage))
	r.GET("/kukushka", a.authorized(a.TabsKukushkaPage))
	r.GET("/lesnik", a.authorized(a.TabsLesnikPage))
	// </summary>
	r.GET("/login", func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
		a.LoginPage(rw, "")
	})
	r.POST("/login", a.Login)
	r.GET("/logout", a.Logout)
	r.GET("/signup", func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
		a.SignupPage(rw, "")
	})
	r.POST("/signup", a.Signup)
}

func (a app) Login(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if login == "" || password == "" {
		a.LoginPage(rw, "Необходимо указать логин и пароль!")
		return
	}
	hash := md5.Sum([]byte(password))
	hashedPass := hex.EncodeToString(hash[:])
	user, err := a.repo.Login(a.ctx, login, hashedPass)
	if err != nil {
		a.LoginPage(rw, "Вы ввели неверный логин или пароль!")
		return
	}
	time64 := time.Now().Unix()
	timeInt := string(time64)
	token := login + password + timeInt
	hashToken := md5.Sum([]byte(token))
	hashedToken := hex.EncodeToString(hashToken[:])
	a.cache[hashedToken] = user
	livingTime := 60 * time.Minute //ВРЕМЯ ЖИЗНИ КУКИША
	expiration := time.Now().Add(livingTime)
	cookie := http.Cookie{Name: "token", Value: url.QueryEscape(hashedToken), Expires: expiration}
	http.SetCookie(rw, &cookie)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (a app) Logout(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	for _, v := range r.Cookies() {
		c := http.Cookie{
			Name:   v.Name,
			MaxAge: -1}
		http.SetCookie(rw, &c)
	}
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (a app) Signup(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	login := strings.TrimSpace(r.FormValue("login"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := strings.TrimSpace(r.FormValue("password"))
	password2 := strings.TrimSpace(r.FormValue("password2"))
	name := strings.TrimSpace(r.FormValue("name"))
	surname := strings.TrimSpace(r.FormValue("surname"))

	if login == "" || email == "" || password == "" || password2 == "" || name == "" || surname == "" {
		a.SignupPage(rw, "Все поля должны быть заполнены!")
		return
	}

	if password != password2 {
		a.SignupPage(rw, "Пароли не совпадают! Попробуйте еще")
		return
	}

	hash := md5.Sum([]byte(password))
	hashedPassword := hex.EncodeToString(hash[:])

	err := a.repo.AddNewUser(a.ctx, login, email, hashedPassword, name, surname)
	if err != nil {
		a.SignupPage(rw, fmt.Sprintf("Ошибка создания пользователя: %v", err))
		return
	}
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (a app) LoginPage(rw http.ResponseWriter, message string) {
	lp := filepath.Join("public", "templates", "login.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	type answer struct {
		Message string
	}
	data := answer{message}
	err = tmpl.ExecuteTemplate(rw, "login", data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) SignupPage(rw http.ResponseWriter, message string) {
	sp := filepath.Join("public", "templates", "signup.html")
	tmpl, err := template.ParseFiles(sp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	type answer struct {
		Message string
	}
	data := answer{message}
	err = tmpl.ExecuteTemplate(rw, "signup", data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) StartPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "index.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "index", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) CoursesPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "courses.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "courses", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) AboutPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "about.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "about", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) LinksPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "links.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "links", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) KeyscoursePage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "keyscourse.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "keyscourse", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) MainTabsPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "tabs.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "tabs", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) TabsLesnikPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "lesnik.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "lesnik", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) TabsCloserPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "closer.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "closer", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) TabsKukushkaPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "templates", "kukushka.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	err = tmpl.ExecuteTemplate(rw, "kukushka", p)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}
