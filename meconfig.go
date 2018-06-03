

package main

import (
	"os"
	//"github.com/therecipe/qt/core"
	"github.com/fabric-meconfig/gui"
	"github.com/therecipe/qt/widgets"
)




//TODO:同时处理与多个节点的连接的配置更新
func main() {

	widgets.NewQApplication(len(os.Args), os.Args)


	me := &gui.MEConfig{}
	me.Construct()




	widgets.QApplication_Exec()
}



