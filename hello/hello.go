package hello

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"encore.dev/rlog"

	"github.com/alexedwards/scs/cockroachdbstore"
	"github.com/alexedwards/scs/v2"
	"github.com/bokwoon95/sq"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
	"go4.org/syncutil"
	"golang.org/x/crypto/bcrypt"
)

/*
//go:embed root.pem
var rootCert []byte
*/

type Usr struct {
	ID    int
	Name  string
	Email string
}

var secrets struct {
	Connstring string //postgres
	RootCert   string //convert to byte
}

var (
	// once is like sync.Once except it re-arms itself on failure
	once syncutil.Once
	// pool is the successfully created database connection pool,
	// or nil when no such pool has been setup yet.
	pool *pgxpool.Pool

	svc *Service
)

//encore:service
type Service struct {
	// Add your dependencies here
	db             *sql.DB
	router         http.Handler
	sessionManager *scs.SessionManager
}

func generateAuthenticationKey(size int) string {
	key := make([]byte, size)
	v, err := rand.Read(key)
	if err != nil {
		//panic(err) // Handle the error according to your application's needs
		rlog.Error("generateAuthenticationKey", "rand.Read", v)
		return ""
	}

	return base64.StdEncoding.EncodeToString(key)
}

func initService() (*Service, error) {
	// Write your service initialization code here.
	svc := &Service{}

	err := svc.setup(context.Background())
	if err != nil {
		log.Println("Error in initService, ", err)
		return nil, err
	}

	// Create the gorilla mux router
	gorillaRouter := mux.NewRouter()

	//use generateAuthenticationKey and store as secret
	csrfMiddleware := csrf.Protect([]byte("32-byte-long-auth-key"))
	api := gorillaRouter.PathPrefix("/api").Subrouter()
	api.Use(csrfMiddleware)

	//unrolled/secure --modify options accordingly
	secureMiddleware := secure.New(secure.Options{
		FrameDeny: true,
	})
	gorillaRouter.Use(secureMiddleware.Handler)
	http.Handle("/", gorillaRouter)

	svc.sessionManager = scs.New()
	svc.sessionManager.Lifetime = 4 * time.Hour
	svc.sessionManager.Store = cockroachdbstore.New(svc.db)
	svc.sessionManager.IdleTimeout = 20 * time.Minute
	svc.sessionManager.Cookie.Name = "session_id"
	//svc.sessionManager.Cookie.Domain = "example.com"
	svc.sessionManager.Cookie.HttpOnly = true
	svc.sessionManager.Cookie.Path = "/"
	svc.sessionManager.Cookie.Persist = true
	svc.sessionManager.Cookie.SameSite = http.SameSiteLaxMode //http.SameSiteStrictMode
	svc.sessionManager.Cookie.Secure = true

	gorillaRouter.HandleFunc("/login", svc.Login)
	gorillaRouter.HandleFunc("/logout", svc.Logout)
	//add HandleFunc gorillaRouter-specific handler(s) here (csrf, etc)

	//cors
	//cors.Default().Handler(gorillaRouter) //--use default or modify options
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://foo.com", "http://foo.com:8080"},
		AllowCredentials: true,
		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	})
	c.Handler(svc.router)

	// Wrap the router with the session middleware.
	svc.router = svc.sessionManager.LoadAndSave(gorillaRouter)

	return svc, nil
}

func (s *Service) Shutdown(force context.Context) {
	s.db.Close()
	pool.Close()
}

//encore:api public raw path=/!fallback
func (s *Service) Fallback(w http.ResponseWriter, req *http.Request) {
	s.router.ServeHTTP(w, req)
}

// Welcome to Encore!
// This is a simple "Hello World" project to get you started.
//
// To run it, execute "encore run" in your favorite shell.

// ==================================================================

// This is a simple REST API that responds with a personalized greeting.
// To call it, run in your terminal:
//
//	curl http://localhost:4000/hello/World
//
//encore:api public path=/hello/:name
func World(ctx context.Context, name string) (*Response, error) {
	//log.Println(string(rootCert))
	rootCAs := x509.NewCertPool()

	//log.Println(secrets.RootCert)

	// Append the embedded root certificate to the certificate pool
	//if !rootCAs.AppendCertsFromPEM(rootCert)) {

	if !rootCAs.AppendCertsFromPEM([]byte(secrets.RootCert)) {
		log.Fatalf("Failed to append root certificate to the pool")
	}

	//connstring := os.Getenv("connstring")
	connstring := secrets.Connstring

	// Attempt to connect
	config, err := pgx.ParseConfig(os.ExpandEnv(connstring))
	if err != nil {
		log.Fatal("error configuring the database: ", err)
	}

	//you download root.crt from your cockroachlabs account
	//root.crt is at $HOME/postgresql
	//openssl x509 -in root.crt -out root.pem

	config.TLSConfig.RootCAs = rootCAs

	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}
	defer conn.Close(context.Background())
	log.Println("Hey! You successfully connected to your CockroachDB cluster.")

	msg := "Hello, " + name + ". You successfully connected to your CockroachDB cluster!"
	return &Response{Message: msg}, nil
}

type Response struct {
	Message string
}

// setup attempts to set up a database connection pool.
func (s *Service) setup(ctx context.Context) error {
	//log.Println(string(rootCert))
	rootCAs := x509.NewCertPool()

	//log.Println(secrets.RootCert)

	// Append the embedded root certificate to the certificate pool
	//if !rootCAs.AppendCertsFromPEM(rootCert)) {

	if !rootCAs.AppendCertsFromPEM([]byte(secrets.RootCert)) {
		log.Fatalf("Failed to append root certificate to the pool")
	}

	//connstring := os.Getenv("connstring")
	connstring := secrets.Connstring

	// Attempt to connect
	config, err := pgx.ParseConfig(os.ExpandEnv(connstring))
	if err != nil {
		log.Fatal("error configuring the database: ", err)
	}

	//you download root.crt from your cockroachlabs account
	//root.crt is at $HOME/postgresql
	//openssl x509 -in root.crt -out root.pem

	config.TLSConfig.RootCAs = rootCAs

	_, err = pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	/*
		//defer conn.Close(context.Background())
		pgpool, err := pgxpool.Connect(ctx, connstring)
		if err != nil {
			return nil, nil, err
		}
	*/

	//use std db, reuse secure config above
	connStr := stdlib.RegisterConnConfig(config)
	s.db, err = sql.Open("pgx", connStr)
	//db, err = sql.Open("pgx", connStr)

	if err != nil {
		log.Println("Error opening db sql ", err)
		return err
	}

	return nil
}

//encore:api public path=/hello3/:name
func (s *Service) World3(ctx context.Context, name string) (*Response, error) {
	var err error
	//pool, db, err = Get(ctx)  --no need to call Get in every API func
	if err != nil {
		log.Println("World2 ", err)
		return nil, err
	}

	if s.db == nil {
		log.Println("error sql open std db ", err)
		return nil, err
	}

	var user Usr
	user, err = sq.FetchOne(s.db, sq.
		Queryf("SELECT {*} FROM users WHERE id = {}", 1).
		SetDialect(sq.DialectPostgres),
		func(row *sq.Row) Usr {
			return Usr{
				ID:    row.Int("id"),
				Name:  row.String("name"),
				Email: row.String("email"),
			}
		},
	)

	if err != nil {
		log.Println("Error in func World ,", err)
		return nil, err
	}

	log.Println(user.ID, " ", user.Name, " ", user.Email)

	msg := "Success sq connection"
	return &Response{Message: msg}, err
}

func (s *Service) authenticate(username, password string) (bool, error) {
	var hashedPassword string
	err := s.db.QueryRowContext(context.Background(), "SELECT password FROM users WHERE name = $1", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			rlog.Error("sql.ErrNoRows", "select sql", err)
			return false, err
		}
		rlog.Error("QueryRowContext", "sql", err)
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		rlog.Error("CompareHashAndPassword", "cmphash", err)
		return false, err
	}

	return true, nil
}

type LoginForm struct {
	Username string `validate:"required"`
	Password string `validate:"required"`
}

// _encore:api public raw method=POST path=/login  --old
//
//encore:api public raw
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {

	var form LoginForm
	if err := r.ParseForm(); err != nil {
		rlog.Error("Login ParseForm", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	//log.Println(r.Form)

	form.Username = r.Form.Get("username")
	form.Password = r.Form.Get("password")

	validate := validator.New()
	if err := validate.Struct(form); err != nil {
		rlog.Error("Login validate Struct form", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	success, err := s.authenticate(form.Username, form.Password)
	if err != nil {
		rlog.Error("Login authenticate", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Fprintf(w, "Fail") //invalid username and/or password bubbles up to user
		return
	}

	// First renew the session token to prevent session fixation
	err = s.sessionManager.RenewToken(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Then make the privilege-level change.
	s.sessionManager.Put(r.Context(), "username", form.Username)

	if success {
		fmt.Fprintf(w, "Success")
		return
	}

}

//encore:api public raw
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	user := s.sessionManager.GetString(r.Context(), "username")
	if user != "" {
		// Renew the session token before logging out
		s.sessionManager.RenewToken(r.Context())

		// Remove the user from the session
		s.sessionManager.Destroy(r.Context())

		fmt.Fprint(w, "Logged out successfully.")
	}
	return
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//encore:api public raw method=POST path=/adduser
func (s *Service) AddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)
	if err != nil {
		rlog.Error("AddUser", "credentials decode", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Hash the password
	hashedPassword, err := hashPassword(credentials.Password)
	if err != nil {
		rlog.Error("AddUser", "hashPassword", err)
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Use pgx.Stdlib as the driver for sql.DB
	pgxConn, err := stdlib.AcquireConn(s.db)
	if err != nil {
		rlog.Error("AddUser", "stdlib.AcquireConn", err)
		http.Error(w, "Failed to acquire connection", http.StatusInternalServerError)
		return
	}
	defer stdlib.ReleaseConn(s.db, pgxConn)

	// Insert the credentials into the database
	// TODO: fix this
	sql := "insert into users(id, name, email, password, verified, created_at) values(2, $1, $2, $3, false, now())"
	_, err = pgxConn.Exec(context.Background(), sql, credentials.Username, "user1@example.com", hashedPassword)
	if err != nil {
		rlog.Error("AddUser", "insert sql", err)
		http.Error(w, "Failed to insert credentials", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Credentials saved successfully")
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
