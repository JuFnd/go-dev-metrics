package usecase

import (
	"context"

	"github.com/go-park-mail-ru/2023_2_Vkladyshi/pkg/models"
)

type ICore interface {
	CreateSession(ctx context.Context, login string) (string, models.Session, error)
	KillSession(ctx context.Context, sid string) error
	FindActiveSession(ctx context.Context, sid string) (bool, error)
	CreateUserAccount(login string, password string, name string, birthDate string, email string) error
	FindUserAccount(login string, password string) (*models.UserItem, bool, error)
	FindUserByLogin(login string) (bool, error)
	GetUserName(ctx context.Context, sid string) (string, error)
	GetUserProfile(login string) (*models.UserItem, error)
	CheckCsrfToken(ctx context.Context, token string) (bool, error)
	CreateCsrfToken(ctx context.Context) (string, error)
	EditProfile(prevLogin string, login string, password string, email string, birthDate string, photo string) error
}
