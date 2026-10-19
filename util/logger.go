package util

import (
	"log"
	"os"
	"strings"
)

type ILogger interface {
	Printf(format string, args ...interface{})
	Println(any ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type Logger struct {
	*log.Logger
	logFile *os.File
}

// Init opens the configured log destination. The special values "stdout" and
// "-" select standard output (useful for containers); every other value is a
// file path, created with mode 0600. A missing directory is an error rather
// than being created silently. Logs carry UTC timestamps so they line up with
// the UTC request log lines.
func (l *Logger) Init(conf *Configuration) error {
	l.Logger = new(log.Logger)
	path := strings.TrimSpace(conf.LogFilePath)
	if strings.EqualFold(path, "stdout") || path == "-" {
		l.logFile = nil
		l.Logger.SetOutput(os.Stdout)
	} else {
		logFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		l.logFile = logFile
		l.Logger.SetOutput(logFile)
	}
	l.Logger.SetFlags(log.LstdFlags | log.LUTC)
	return nil
}

// Close releases the log file. It is a safe no-op when the logger writes to
// standard output (or was never initialized), so callers may always defer it.
func (l *Logger) Close() error {
	if l == nil || l.logFile == nil {
		return nil
	}
	return l.logFile.Close()
}

// Infof, Warnf and Errorf log a security-relevant message with its severity
// prefixed; they are the audit-log counterparts of the timestamped Printf.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Printf("INFO: "+format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Printf("WARN: "+format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Printf("ERROR: "+format, args...)
}
