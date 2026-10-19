package util

import (
	"log"
	"os"
)

type ILogger interface {
	Printf(format string, args ...interface{})
	Println(any ...interface{})
}

type Logger struct {
	*log.Logger
	logFile *os.File
}

func (l *Logger) Init(conf *Configuration) error {
	l.Logger = new(log.Logger)
	logFile, err := os.OpenFile(conf.LogFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		return err
	}
	l.logFile = logFile
	l.Logger.SetOutput(logFile)
	// remove timestamp
	l.Logger.SetFlags(0)
	return nil
}

func (l *Logger) Close() error {
	return l.logFile.Close()
}
