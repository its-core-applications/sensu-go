package umich

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/backend/authentication/jwt"
	"github.com/sensu/sensu-go/types"
	krb_client "gopkg.in/jcmturner/gokrb5.v7/client"
	krb_config "gopkg.in/jcmturner/gokrb5.v7/config"
	ldap "gopkg.in/ldap.v3"
)

const Type = "umich"

type Provider struct {
	// ObjectMeta contains the name, namespace, labels and annotations
	corev2.ObjectMeta `json:"metadata"`
}

func (p *Provider) Authenticate(ctx context.Context, username, password string) (*corev2.Claims, error) {
	if username == "" || password == "" {
		return nil, errors.New("the username and the password must not be empty")
	}

	cfg, err := krb_config.Load("/etc/krb5.conf")
	// should probably just fix this in the config, but eh
	cfg.LibDefaults.DNSLookupKDC = true

	krb := krb_client.NewClientWithPassword(username, "UMICH.EDU", password, cfg)
	err = krb.Login()
	krb.Destroy()

	if err != nil {
		return nil, err
	}

	return p.claims(username)
}

func (p *Provider) Refresh(ctx context.Context, providerClaims corev2.AuthProviderClaims) (*corev2.Claims, error) {
	return p.claims(providerClaims.UserID)
}

func (p *Provider) GetObjectMeta() corev2.ObjectMeta {
	return p.ObjectMeta
}

func (p *Provider) Name() string {
	return p.ObjectMeta.Name
}

func (p *Provider) Type() string {
	return Type
}

func (p *Provider) URIPath() string {
	return ""
}

func (p *Provider) Validate() error {
	p.ObjectMeta.Name = Type
	return nil
}

func (p *Provider) claims(username string) (*corev2.Claims, error) {
	groups, err := p.groups(username)
	if err != nil {
		return nil, err
	}

	user := &types.User{
		Username: username,
		Groups:   groups,
	}

	claims, err := jwt.NewClaims(user)
	if err != nil {
		return nil, err
	}

	claims.Provider = corev2.AuthProviderClaims{
		ProviderID: p.Name(),
		UserID:     username,
	}

	return claims, nil
}

func (p *Provider) groups(username string) ([]string, error) {
	conn, err := ldap.Dial("tcp", "ldap.umich.edu:389")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.UnauthenticatedBind("")
	if err != nil {
		return nil, err
	}

	attrs := []string{"cn", "member"}

	search := ldap.NewSearchRequest(
		"ou=Groups,dc=umich,dc=edu",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn=blackops)",
		attrs,
		nil,
	)

	res, err := conn.Search(search)
	if err != nil {
		return nil, err
	}

	members := res.Entries[0].GetAttributeValues("member")
	for _, memb := range members {
		if strings.HasPrefix(memb, fmt.Sprintf("uid=%s,", username)) {
			return []string{"blackops"}, nil
		}
	}

	return []string{"readonly"}, nil
}

func (p *Provider) StorePrefix() string {
	return ""
}

func (p *Provider) SetNamespace(namespace string) {
	p.Namespace = namespace
}
