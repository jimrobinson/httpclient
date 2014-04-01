package httpclient

import (
	"net/url"
)

type Credentials interface {
	Username(uri *url.URL, realm string) (username string, err error)
	Password(uri *url.URL, realm string) (password string, err error)
}

func NewCredentials(username, password string) Credentials {
	return &credentials{
		username: username,
		password: password,
	}
}

type credentials struct {
	username string
	password string
}

func (c *credentials) Username(uri *url.URL, realm string) (username string, err error) {
	return c.username, nil
}

func (c *credentials) Password(uri *url.URL, realm string) (password string, err error) {
	return c.password, nil
}
