// Copyright (c) 2023 Manifold Finance, Inc.
// The Universal Permissive License (UPL), Version 1.0
// Subject to the condition set forth below, permission is hereby granted to any person obtaining a copy of this software, associated documentation and/or data (collectively the “Software”), free of charge and under any and all copyright rights in the Software, and any and all patent rights owned or freely licensable by each licensor hereunder covering either (i) the unmodified Software as contributed to or provided by such licensor, or (ii) the Larger Works (as defined below), to deal in both
// (a) the Software, and
// (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if one is included with the Software (each a “Larger Work” to which the Software is contributed by such licensors),
// without restriction, including without limitation the rights to copy, create derivative works of, display, perform, and distribute the Software and make, use, sell, offer for sale, import, export, have made, and have sold the Software and the Larger Work(s), and to sublicense the foregoing rights on either these or other terms.
// This license is subject to the following condition:
// The above copyright notice and either this complete permission notice or at a minimum a reference to the UPL must be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// This script ensures source code files have copyright license headers. See license.sh for more information.
package freelay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/draganm/bolted"
	boltedsftp "github.com/draganm/bolted-sftp"
	"github.com/draganm/bolted/dbpath"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var (
	sshKeyPath = dbpath.ToPath("server_ssh_key")
)

func StartSFTP(ctx context.Context, addr string, db bolted.Database) (string, error) {
	pk, err := getSSHKeyPayloadExecuted(db)
	if err != nil {
		return "", fmt.Errorf("while loading ssh private key: %w", err)
	}

	if pk == nil {
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", fmt.Errorf("while generating new ssh private key: %w", err)
		}

		if err := setSSHKeyPayloadExecuted(db, pk); err != nil {
			return "", fmt.Errorf("while storing new ssh private key: %w", err)
		}
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() != "debug" {
				return nil, errors.New("nope")
			}

			if string(password) != "debug" {
				return nil, errors.New("nope")
			}
			return &ssh.Permissions{}, nil
		},
	}

	hostSigner, err := ssh.NewSignerFromKey(pk)
	if err != nil {
		return "", fmt.Errorf("while creating signer from private key: %w", err)
	}

	zcfg := zap.NewDevelopmentConfig()
	zlog, _ := zcfg.Build()
	log := zapr.NewLogger(zlog)
	cfg.AddHostKey(hostSigner)
	addr, err = boltedsftp.Serve(ctx, addr, db, cfg, log)
	return addr, err
}

func getSSHKeyPayloadExecuted(db bolted.Database) (*rsa.PrivateKey, error) {
	var pk *rsa.PrivateKey

	if err := bolted.SugaredRead(db, func(tx bolted.SugaredReadTx) error {
		if !tx.Exists(sshKeyPath) {
			return nil
		}
		var err error
		pk, err = x509.ParsePKCS1PrivateKey(tx.Get(sshKeyPath))
		if err != nil {
			return fmt.Errorf("while unmarhsalling server ssh key: %w", err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return pk, nil
}

func setSSHKeyPayloadExecuted(db bolted.Database, pk *rsa.PrivateKey) error {
	return bolted.SugaredWrite(db, func(tx bolted.SugaredWriteTx) error {
		tx.Put(sshKeyPath, x509.MarshalPKCS1PrivateKey(pk))
		return nil
	})
}
