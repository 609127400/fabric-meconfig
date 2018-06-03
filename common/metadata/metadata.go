
package metadata

import (
	"fmt"
	"runtime"
)

//TODO:像fabric源码编译一样，若有Makefile了，则meta数据源移到Makefile中去

//本程序版本号
var Version string
//运行的fabric的版本号
var FabricVersion string = "1.0"

const ProgramName = "meconfig"

func GetVersionInfo() string {
	if Version == "" {
		Version = "development build"
	}

	return fmt.Sprintf("%s:\n Version: %s\n Go version: %s\n OS/Arch: %s",
		ProgramName, Version, runtime.Version(),
		fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}
