package cognitotokenverifier

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

const (
	keysURLTemplate = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
)

type Config struct {
	Region string
	PoolID string
}

type verifier struct {
	cprovider *cognito.CognitoIdentityProvider
	cfg       *Config
	keysURL   string
}

func InitVerifier(cfg *Config) (*verifier, error) {
	keysURL := fmt.Sprintf(keysURLTemplate, cfg.Region, cfg.PoolID)
	c := &aws.Config{Region: aws.String(cfg.Region)}
	sess, err := session.NewSession(c)
	if err != nil {
		return nil, err
	}
	cp := cognito.New(sess)
	return &verifier{
		cprovider: cp,
		cfg:       cfg,
		keysURL:   keysURL,
	}, nil
}

// Verify verifies the ID token from cognito
// Read documentation below:
// https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/
func (v verifier) Verify(ctx context.Context, token string) error {
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return v.getMatchingPublicKey(ctx, token)
	})
	if err != nil {
		if validationError, ok := err.(*jwt.ValidationError); ok {
			if validationError.Is(jwt.ErrTokenExpired) {
				return ErrTokenExpired
			}
		}
		return err
	}
	return nil
}

// GetUserAttributesByToken returns user attributes
// token must be verified before that
func (v verifier) GetUserAttributesByToken(token string) (map[string]string, error) {
	i := &cognito.GetUserInput{
		AccessToken: aws.String(token),
	}
	res, err := v.cprovider.GetUser(i)
	if err != nil {
		return nil, err
	}
	attrs := make(map[string]string, len(res.UserAttributes))
	for _, vv := range res.UserAttributes {
		attrs[*vv.Name] = *vv.Value
	}
	return attrs, nil
}

func (v verifier) getMatchingPublicKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	keySet, err := jwk.Fetch(ctx, v.keysURL)
	if err != nil {
		return nil, err
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, ErrNoKidHeader
	}
	key, exist := keySet.LookupKeyID(kid)
	if !exist {
		return nil, ErrKidsDontMatch
	}
	pub, err := jwk.PublicRawKeyOf(key)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
