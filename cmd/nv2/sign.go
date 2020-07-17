package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/notaryproject/nv2/pkg/signature"
	"github.com/notaryproject/nv2/pkg/signature/x509"
	"github.com/urfave/cli/v2"
)

const signerID = "nv2"

var signCommand = &cli.Command{
	Name:      "sign",
	Usage:     "signs artifacts or images",
	ArgsUsage: "[<scheme://reference>]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "method",
			Aliases:  []string{"m"},
			Usage:    "siging method",
			Required: true,
		},
		&cli.StringFlag{
			Name:      "key",
			Aliases:   []string{"k"},
			Usage:     "siging key file",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:      "cert",
			Aliases:   []string{"c"},
			Usage:     "siging cert",
			TakesFile: true,
		},
		&cli.DurationFlag{
			Name:    "expiry",
			Aliases: []string{"e"},
			Usage:   "expire duration",
		},
		&cli.StringSliceFlag{
			Name:    "references",
			Aliases: []string{"r"},
			Usage:   "original references",
		},
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "write signature to a specific path",
		},
	},
	Action: runSign,
}

func runSign(ctx *cli.Context) error {
	scheme, err := getSchemeForSigning(ctx)
	if err != nil {
		return err
	}

	content, err := prepareContentForSigning(ctx)
	if err != nil {
		return err
	}

	sig, err := scheme.Sign(signerID, content)
	if err != nil {
		return err
	}
	sigma, err := signature.Pack(content, sig)
	if err != nil {
		return err
	}

	path := ctx.String("output")
	if path == "" {
		path = strings.Split(content.Manifests[0].Digest, ":")[1] + ".nv2"
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(sigma)
}

func prepareContentForSigning(ctx *cli.Context) (signature.Content, error) {
	var (
		manifest signature.Manifest
		err      error
	)
	if uri := ctx.Args().First(); uri != "" {
		manifest, err = getManfestsFromURI(uri)
	} else {
		manifest, err = getManifestFromReader(os.Stdin)
	}
	if err != nil {
		return signature.Content{}, err
	}

	manifest.References = ctx.StringSlice("references")
	now := time.Now()
	nowUnix := now.Unix()
	content := signature.Content{
		NotBefore: nowUnix,
		IssuedAt:  nowUnix,
		Manifests: []signature.Manifest{
			manifest,
		},
	}
	if expiry := ctx.Duration("expiry"); expiry != 0 {
		content.Expiration = now.Add(expiry).Unix()
	}

	return content, nil
}

func getSchemeForSigning(ctx *cli.Context) (*signature.Scheme, error) {
	scheme := signature.NewScheme()
	switch method := ctx.String("method"); method {
	case "x509":
		signer, err := x509.NewSignerFromFiles(ctx.String("key"), ctx.String("cert"))
		if err != nil {
			return nil, err
		}
		scheme.RegisterSigner(signerID, signer)
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", method)
	}
	return scheme, nil
}
