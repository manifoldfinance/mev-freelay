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
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/draganm/bolted"
	"github.com/draganm/bolted/dbpath"
	"github.com/draganm/kartusche/runtime"
	"go.uber.org/zap"
)

type Web interface {
	HTTPServer() *http.Server
	Listener() *net.Listener
}

type web struct {
	srv      *http.Server
	listener *net.Listener
}

func NewWeb(addr, apiAddr, relayAddr, dbPrefix, network, pubKey string) (*web, error) {
	dir := "./web"
	pth := fmt.Sprintf("%s.runtime.db", dbPrefix)

	_, err := os.Stat(pth)
	if err == nil {
		if err := os.Remove(pth); err != nil {
			return nil, fmt.Errorf("while removing old runtime: %w", err)
		}
	}

	_, err = os.Stat(pth)
	if os.IsNotExist(err) {
		err = runtime.InitializeNew(pth, dir)
	}

	if err != nil {
		return nil, fmt.Errorf("while initializing runtime: %w", err)
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("while creating listener: %w", err)
	}

	rt, err := runtime.Open(pth, zap.L().Sugar())
	if err != nil {
		return nil, fmt.Errorf("while starting runtime: %w", err)
	}

	envVarPth := dbpath.ToPath("data")
	if err := rt.Update(func(tx bolted.SugaredWriteTx) error {
		if tx.Exists(envVarPth) {
			tx.Delete(envVarPth)
		}
		tx.CreateMap(envVarPth)
		tx.Put(envVarPth.Append("API_ADDR"), []byte(fmt.Sprintf("http://localhost%s", apiAddr)))
		tx.Put(envVarPth.Append("RELAY_ADDR"), []byte(fmt.Sprintf("http://localhost%s", relayAddr)))
		tx.Put(envVarPth.Append("NETWORK"), []byte(network))
		tx.Put(envVarPth.Append("PUB_KEY"), []byte(pubKey))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("while setting env vars: %w", err)
	}

	srv := http.Server{
		Handler: rt,
	}

	return &web{
		listener: &l,
		srv:      &srv,
	}, nil
}

func (w *web) HTTPServer() *http.Server {
	return w.srv
}

func (w *web) Listener() *net.Listener {
	return w.listener
}
