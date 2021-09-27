package main

import (
	"crypto/x509"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault/keyvaultapi"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
	"github.com/notaryproject/notation-go-lib/signature/jws"
	"github.com/notaryproject/notation/internal/cmd"
	jwtazure "github.com/shizhMSFT/go-jwt-azure"
	"github.com/urfave/cli/v2"
)

func getAzureClient(ctx *cli.Context) (keyvaultapi.BaseClientAPI, error) {
	cred := strings.SplitN(ctx.String(flagAzureCredential.Name), ":", 3)
	if len(cred) != 3 {
		return nil, errors.New("invalid azure credential")
	}
	tenantID, clientID, secret := cred[0], cred[1], cred[2]

	azureEnv := azure.PublicCloud
	oauthConfig, err := adal.NewOAuthConfig(azureEnv.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}
	spToken, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, secret, strings.TrimSuffix(azureEnv.KeyVaultEndpoint, "/"))
	if err != nil {
		return nil, err
	}

	client := keyvault.New()
	client.Authorizer = autorest.NewBearerAuthorizer(spToken)
	return client, nil
}

func getAzureSigner(ctx *cli.Context) (notation.Signer, error) {
	// get remote key
	kid := ctx.String(flagAzure.Name)
	client, err := getAzureClient(ctx)
	if err != nil {
		return nil, err
	}
	key, err := jwtazure.NewKey(client, kid)
	if err != nil {
		return nil, err
	}

	// for demo purpose, we use specific signing method
	signer, err := jws.NewSignerWithKeyID(jwtazure.SigningMethodPS512, key, kid)
	if err != nil {
		return nil, err
	}
	if endpoint := ctx.String(cmd.FlagTimestamp.Name); endpoint != "" {
		signer.TSA = timestamp.NewHTTPTimestamper(nil, endpoint)
	}
	return signer, nil
}

func getAzureVerifier(ctx *cli.Context) (notation.Verifier, error) {
	// get remote key
	kid := ctx.String(flagAzure.Name)
	client, err := getAzureClient(ctx)
	if err != nil {
		return nil, err
	}
	key, err := jwtazure.NewKey(client, kid)
	if err != nil {
		return nil, err
	}

	// for demo purpose, we use specific signing method
	vKey, err := jws.NewVerificationKeyWithKeyID(jwtazure.SigningMethodPS512, key, kid)
	if err != nil {
		return nil, err
	}

	// construct verifier
	verifier := jws.NewVerifier([]*jws.VerificationKey{vKey})
	verifier.VerifyOptions.Roots = x509.NewCertPool()
	return verifier, nil
}
