package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Log is the logrus service
var Log *logrus.Logger

func init() {
	// f, err := os.OpenFile("ob1-scanner.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// Log.Out = f
	logrus.SetOutput(os.Stdout)
}
