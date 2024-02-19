package logger

import (
	"github.com/sirupsen/logrus"
)

var (
	DefaultLogger = newDefaultLogger()
)

func newDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{DisableQuote: true})
	logger.SetLevel(logrus.InfoLevel) // TODO
	return logger
}

func GetLogger() *logrus.Logger {
	return DefaultLogger
}
