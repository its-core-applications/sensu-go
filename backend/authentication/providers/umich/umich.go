package umich

import (
	"bufio"
	"context"
	"errors"
	"os"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/backend/authentication/jwt"
	"github.com/sensu/sensu-go/types"
	krb_client "gopkg.in/jcmturner/gokrb5.v7/client"
	krb_config "gopkg.in/jcmturner/gokrb5.v7/config"
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

func (p *Provider) Refresh(ctx context.Context, claims *corev2.Claims) (*corev2.Claims, error) {
	return p.claims(claims.Provider.UserID)
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
	file, err := os.Open("/etc/sensu/blackops")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == username {
			return []string{"blackops"}, nil
		}
	}

	return nil, errors.New("not found in authorization file /etc/sensu/blackops")
}

func (p *Provider) StorePrefix() string {
	return ""
}

func (p *Provider) SetNamespace(namespace string) {
	p.Namespace = namespace
}

func (p *Provider) RBACName() string {
	return ""
}

func (p *Provider) SetObjectMeta(meta corev2.ObjectMeta) {
	p.ObjectMeta = meta
}
