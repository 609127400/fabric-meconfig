
package gui



import (
    "github.com/therecipe/qt/widgets"
)


type TopicLayout interface {
    widgets.QLayout_ITF
    //构造自身页面
    construct()
    //获取配置数据（只针对配置主题页面）
    getConfigurationData() []byte
}


