package delivery

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-park-mail-ru/2023_2_Vkladyshi/authorization/usecase"
	"github.com/go-park-mail-ru/2023_2_Vkladyshi/errors"
	"github.com/go-park-mail-ru/2023_2_Vkladyshi/pkg/requests"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type API struct {
	core usecase.ICore
	lg   *slog.Logger
	mx   *http.ServeMux
	deliveryStatusCounter *prometheus.CounterVec
}

func (a *API) ListenAndServe() {
	err := http.ListenAndServe(":8081", a.mx)
	if err != nil {
		a.lg.Error("ListenAndServe error", "err", err.Error())
	}
}

func (a *API) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func GetApi(c *usecase.Core, l *slog.Logger) *API {
	api := &API{
		core: c,
		lg:   l.With("module", "api"),
		mx:   &http.ServeMux{},
		deliveryStatusCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "delivery_status",
				Help: "Number of package deliveries with different statuses.",
			},
			[]string{"status"},
		),
	}
	mx := http.NewServeMux()
	mx.HandleFunc("/signup", api.Signup)
	mx.HandleFunc("/signin", api.Signin)
	mx.HandleFunc("/logout", api.LogoutSession)
	mx.HandleFunc("/authcheck", api.AuthAccept)

	api.mx = mx
	prometheus.MustRegister(api.deliveryStatusCounter)
	api.mx.Handle("/metrics", http.HandlerFunc(api.MetricsHandler))

	return api
}

func (a *API) SendResponse(w http.ResponseWriter, response requests.Response) {
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		a.lg.Error("failed to pack json", "err", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonResponse)
	if err != nil {
		a.lg.Error("failed to send response", "err", err.Error())
	}
}

func (a *API) LogoutSession(w http.ResponseWriter, r *http.Request) {
	response := requests.Response{Status: http.StatusOK, Body: nil}

	session, err := r.Cookie("session_id")
	if err == http.ErrNoCookie {
		response.Status = http.StatusUnauthorized
		a.deliveryStatusCounter.WithLabelValues("logout").Inc()
		a.SendResponse(w, response)
		return
	}

	found, _ := a.core.FindActiveSession(r.Context(), session.Value)
	if !found {
		response.Status = http.StatusUnauthorized
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("logout").Inc()
		return
	} else {
		err := a.core.KillSession(r.Context(), session.Value)
		if err != nil {
			a.lg.Error("failed to kill session", "err", err.Error())
		}
		session.Expires = time.Now().AddDate(0, 0, -1)
		http.SetCookie(w, session)
	}

	a.deliveryStatusCounter.WithLabelValues("logout").Inc()
	a.SendResponse(w, response)
}

func (a *API) AuthAccept(w http.ResponseWriter, r *http.Request) {
	response := requests.Response{Status: http.StatusOK, Body: nil}
	var authorized bool

	session, err := r.Cookie("session_id")
	if err == nil && session != nil {
		authorized, _ = a.core.FindActiveSession(r.Context(), session.Value)
	}

	if !authorized {
		response.Status = http.StatusUnauthorized
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("AuthSuccess").Inc()
		return
	}
	login, err := a.core.GetUserName(r.Context(), session.Value)
	if err != nil {
		a.lg.Error("auth accept error", "err", err.Error())
		response.Status = http.StatusInternalServerError
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("AuthSuccess").Inc()
		return
	}

	authCheckResponse := requests.AuthCheckResponse{Login: login}
	response.Body = authCheckResponse

	a.SendResponse(w, response)
	a.deliveryStatusCounter.WithLabelValues("AuthSuccess").Inc()
}

func (a *API) Signin(w http.ResponseWriter, r *http.Request) {
	response := requests.Response{Status: http.StatusOK, Body: nil}
	if r.Method != http.MethodPost {
		response.Status = http.StatusMethodNotAllowed
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
		return
	}

	var request requests.SigninRequest

	body, err := io.ReadAll(r.Body)
	if err != nil {
		response.Status = http.StatusBadRequest
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
		return
	}

	if err = json.Unmarshal(body, &request); err != nil {
		response.Status = http.StatusBadRequest
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
		return
	}

	user, found, err := a.core.FindUserAccount(request.Login, request.Password)
	if err != nil {
		a.lg.Error("Signin error", "err", err.Error())
		response.Status = http.StatusInternalServerError
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
		return
	}
	if !found {
		response.Status = http.StatusUnauthorized
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
		return
	} else {
		sid, session, _ := a.core.CreateSession(r.Context(), user.Login)
		cookie := &http.Cookie{
			Name:     "session_id",
			Value:    sid,
			Path:     "/",
			Expires:  session.ExpiresAt,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

	a.SendResponse(w, response)
	a.deliveryStatusCounter.WithLabelValues("Signin").Inc()
}

func (a *API) Signup(w http.ResponseWriter, r *http.Request) {
	response := requests.Response{Status: http.StatusOK, Body: nil}
	if r.Method != http.MethodPost {
		response.Status = http.StatusMethodNotAllowed
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
		return
	}

	var request requests.SignupRequest

	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.lg.Error("Signup error", "err", err.Error())
		response.Status = http.StatusBadRequest
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
		return
	}

	err = json.Unmarshal(body, &request)
	if err != nil {
		a.lg.Error("Signup error", "err", err.Error())
		response.Status = http.StatusBadRequest
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
		return
	}

	found, err := a.core.FindUserByLogin(request.Login)
	if err != nil {
		a.lg.Error("Signup error", "err", err.Error())
		response.Status = http.StatusInternalServerError
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
		return
	}
	if found {
		response.Status = http.StatusConflict
		a.SendResponse(w, response)
		a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
		return
	}
	err = a.core.CreateUserAccount(request.Login, request.Password, request.Name, request.BirthDate, request.Email)
	if err == errors.InvalideEmail {
		a.lg.Error("create user error", "err", err.Error())
		response.Status = http.StatusBadRequest
	}
	if err != nil {
		a.lg.Error("failed to create user account", "err", err.Error())
		response.Status = http.StatusBadRequest
	}

	a.SendResponse(w, response)
	a.deliveryStatusCounter.WithLabelValues("Signup").Inc()
}