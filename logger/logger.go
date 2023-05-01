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
package logger

import (
	"fmt"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	zlogger *logger
)

func init() {
	if zlogger != nil {
		return
	}

	l := newZLog()
	zlogger = newLogger(&l)
}

func newZLog() logr.Logger {
	zcfg := zap.NewDevelopmentConfig()
	zcfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zcfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	zcfg.DisableStacktrace = true
	zcfg.DisableCaller = true
	zcfg.Level = zap.NewAtomicLevelAt(zapcore.Level(-2))
	zlog, _ := zcfg.Build()
	l := zapr.NewLogger(zlog)
	return l
}

func Info(msg string, keysAndValues ...interface{}) {
	zlogger.Info(msg, keysAndValues...)
}

func Error(err error, msg string, keysAndValues ...interface{}) {
	zlogger.Error(err, msg, keysAndValues...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	zlogger.Debug(msg, keysAndValues...)
}

func WithValues(keysAndValues ...interface{}) *logger {
	return zlogger.WithValues(keysAndValues...)
}

func SetVersion(v string) {
	if len(v) > 7 {
		v = v[:7]
	}
	zlogger.SetVersion(v)
}

func includeVersion(v, msg string) string {
	return fmt.Sprintf("%s\t%s", v, msg)
}

type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(err error, msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	WithValues(keysAndValues ...interface{}) *logger
	Z() *logr.Logger
}

type logger struct {
	z *logr.Logger
	v string
}

func newLogger(zlogr *logr.Logger) *logger {
	return &logger{z: zlogr, v: "unknown"}
}

func (l *logger) Info(msg string, keysAndValues ...interface{}) {
	l.z.Info(includeVersion(l.v, msg), keysAndValues...)
}

func (l *logger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.z.Error(err, includeVersion(l.v, msg), keysAndValues...)
}

func (l *logger) Debug(msg string, keysAndValues ...interface{}) {
	l.z.V(1).Info(includeVersion(l.v, msg), keysAndValues...)
}

func (l *logger) WithValues(keysAndValues ...interface{}) *logger {
	zll := l.z.WithValues(keysAndValues...)
	return &logger{z: &zll, v: l.v}
}

func (l *logger) Z() *logr.Logger {
	return l.z
}

func (l *logger) SetVersion(v string) {
	l.v = v
}
