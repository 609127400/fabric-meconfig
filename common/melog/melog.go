
package melog

import (
    "os"
    "log"
)


func GetOneLogger(name string) *log.Logger {
    logfile, err := os.Create("client.log")
    if err != nil {
        log.Fatalln("create client log file error")
    }
    logger = log.New(logfile,"[Info]", log.Llongfile)
    logger.SetPrefix(fmt.Sprintf("[%s-Debug]", name))
    logger.SetFlags(log.Lshortfile)

    return logger
}
