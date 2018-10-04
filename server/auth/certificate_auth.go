package server

import (
	"github.com/nats-io/gnatsd/server"
)

type CertificateLegacyAuth func(client server.ClientAuthentication) bool

type CertificateAuth struct {
	certificateClients map[string]*server.CertificateClient
	fallbackAuth CertificateLegacyAuth
}

func NewCertificateAuth(certificateClients []*server.CertificateClient, fallbackAuth CertificateLegacyAuth) *CertificateAuth {
	certificateAuth := &CertificateAuth{
		certificateClients: make(map[string]*server.CertificateClient),
		fallbackAuth: fallbackAuth,
	}
	for _, client := range certificateClients {
		certificateAuth.certificateClients[client.ClientName] = client
	}
	return certificateAuth
}

func (a *CertificateAuth) Check(c server.ClientAuthentication) bool {
	if c.IsLegacyBoshClient() {
		if c.GetOpts().Username == "" {
			return false
		}

		return a.fallbackAuth(c)
	} else {
		clientName, clientID, err := c.GetCertificateClientNameAndID()

		if err != nil {
			return false
		}

		if clientName == "" {
			return false
		}

		client, ok := a.certificateClients[clientName]
		if !ok {
			return false
		}

		c.RegisterCertificateClient(client, clientID)
		return true
	}
}
