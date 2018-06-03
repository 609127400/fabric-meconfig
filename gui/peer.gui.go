
package gui

import (
    //"github.com/therecipe/qt/core"
    "github.com/therecipe/qt/widgets"
)


type peerConfig struct {
    label *widgets.QLabel



    is_constructed bool
    *widgets.QVBoxLayout
}

func (p *peerConfig) construct() {
    p.label = widgets.NewQLabel2("P E E R - C O N F I G",nil,0)
    p.QVBoxLayout = widgets.NewQVBoxLayout()
    p.AddWidget(p.label,0,0)

    p.is_constructed = true
}

func (p *peerConfig) getConfigurationData() []byte {
    return nil
}

type peerCommand struct {
    label *widgets.QLabel



    is_constructed bool
    *widgets.QVBoxLayout
}

func (p *peerCommand) construct() {
    p.label = widgets.NewQLabel2("P E E R - C O M M A N D",nil,0)
    p.QVBoxLayout = widgets.NewQVBoxLayout()
    p.AddWidget(p.label,0,0)

    p.is_constructed = true
}

func (p *peerCommand) getConfigurationData() []byte {
    return nil
}
