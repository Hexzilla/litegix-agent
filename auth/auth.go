package auth

import (
	"time"
)

type AuthInterface interface {
	CreateAuth(string, *TokenDetails) error
	FetchAuth(string) (string, error)
	DeleteRefresh(string) error
	DeleteTokens(*AccessDetails) error
}

type Service struct {
	userId      string
	tokenUuid   string
	refreshUuid string
	updated     time.Time
}

var _ AuthInterface = &Service{}

func NewAuth() *Service {
	return &Service{}
}

type AccessDetails struct {
	TokenUuid string
	UserId    string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	TokenUuid    string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

//Save token metadata to Redis
func (service *Service) CreateAuth(userId string, td *TokenDetails) error {
	//at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	//rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	service.userId = userId
	service.tokenUuid = td.TokenUuid
	service.refreshUuid = td.RefreshToken
	service.updated = now
	return nil
}

//Check the metadata saved
func (service *Service) FetchAuth(tokenUuid string) (string, error) {
	return service.userId, nil
}

//Once a user row in the token table
func (service *Service) DeleteTokens(authD *AccessDetails) error {
	service.tokenUuid = ""
	service.refreshUuid = ""
	return nil
}

func (service *Service) DeleteRefresh(refreshUuid string) error {
	service.refreshUuid = ""
	return nil
}
