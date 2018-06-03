
package gui

import(
    "os"
    "log"
    //"github.com/therecipe/qt/core"
    "github.com/therecipe/qt/widgets"
    "github.com/fabric-meconfig/common/protos"
)

var (
    logger *log.Logger //------全局日志对象
    meconfig *MEConfig //------MEConfig全局对象
)

func init() {
    client_log, err := os.Create("gui.log")
    if err != nil {
        log.Fatalln("create gui log file error")
    }
    logger = log.New(client_log,"[Info]", log.Llongfile)
    logger.SetPrefix("[MEClient-GUI-Debug]")
    logger.SetFlags(log.Lshortfile)
}

type head struct {
    topicComboBox *widgets.QComboBox
    explainBowser *widgets.QTextBrowser

    nodeAddressLineEdit *widgets.QLineEdit
    testConnectButton *widgets.QPushButton
    testResultLabel *widgets.QLabel
    lastTopicComboBoxIndex int
    *widgets.QGridLayout
}

func (h *head) construct() {
    h.topicComboBox = widgets.NewQComboBox(nil)
    h.topicComboBox.AddItems([]string{"PEER_CONFIG","PEER_COMMAND","ORDERER_CONFIG","ORDERER_CHANNEL_CONFIG","ORDERER_COMMAND"})
    h.explainBowser  = widgets.NewQTextBrowser(nil)
    h.explainBowser.SetMinimumSize2(450,30)
    h.explainBowser.SetText("explain")
    h.explainBowser.SetWordWrapMode(1)
    h.nodeAddressLineEdit = widgets.NewQLineEdit(nil)
    h.nodeAddressLineEdit.SetPlaceholderText("127.0.0.1")
    h.nodeAddressLineEdit.SetText("127.0.0.1:10000")
    h.testConnectButton = widgets.NewQPushButton2("连接测试", nil)
    h.testResultLabel = widgets.NewQLabel(nil,0)

    h.topicComboBox.ConnectCurrentIndexChanged( func(index int){ topicComboBoxCurrentIndexChanged(index) } )
    h.testConnectButton.ConnectClicked(func(_ bool) { testConnectButtonClick() })

    testLayout := widgets.NewQHBoxLayout()
    testLayout.AddWidget(widgets.NewQLabel2("MEServer地址：", nil, 0), 0, 0)
    testLayout.AddWidget(h.nodeAddressLineEdit, 0, 0)
    testLayout.AddWidget(h.testConnectButton, 0, 0)

    h.QGridLayout = widgets.NewQGridLayout2()
    h.QGridLayout.AddWidget3(h.topicComboBox,0,0,1,1,0)
    h.QGridLayout.AddWidget3(h.explainBowser,0,3,2,3,0)
    h.QGridLayout.AddLayout2(testLayout,1,0,1,3,0)
    h.QGridLayout.AddWidget3(h.testResultLabel,0,1,1,2,0)
}

func (h *head) GetExplainLabel() *widgets.QTextBrowser {
    return h.explainBowser
}

func (h *head) EchoExplain(s string) {
    h.explainBowser.SetText(s)
}

type body struct {
    //topics map[mecommon.Topic]widgets.QLayout_ITF
    topics map[mecommon.Topic]TopicLayout
    //当前的主题，改变该值的函数有
    //1.gui.event.go - topicComboBoxCurrentIndexChanged
    //2.orderer.event.go - addOneSpecButtonClick
    topic mecommon.Topic
    //每个具体的界面都存放在stackedtopics的每个Page中
    stackedtopics *widgets.QStackedWidget
    *widgets.QGridLayout
}

func (b *body) construct() {
    //topicComboBox.AddItems([]string{"PEER_CONFIG","PEER_COMMAND","ORDERER_CONFIG","ORDERER_CHANNEL_CONFIG","ORDERER_COMMAND"})
    peerConfig := &peerConfig{}
    peerCommand := &peerCommand{}
    ordererConfig := &ordererConfig{}
    ordererChannelConfig := &ordererChannelConfig{}
    ordererCommand := &ordererCommand{}

    peerConfig.construct()
    peerCommand.construct()
    ordererConfig.construct()
    ordererChannelConfig.construct()
    ordererCommand.construct()

    b.topics = make(map[mecommon.Topic]TopicLayout)
    b.topics[mecommon.Topic_PEER_CONFIG] = peerConfig
    b.topics[mecommon.Topic_PEER_COMMAND] = peerCommand
    b.topics[mecommon.Topic_ORDERER_CONFIG] = ordererConfig
    b.topics[mecommon.Topic_ORDERER_CHANNEL_CONFIG] = ordererChannelConfig
    b.topics[mecommon.Topic_ORDERER_COMMAND] = ordererCommand

    b.stackedtopics = widgets.NewQStackedWidget(nil)

    //Topic_PEER_CONFIG界面
    peerConfigWidget := widgets.NewQWidget(nil,0)
    peerConfigWidget.SetLayout(peerConfig)
    //Topic_PEER_COMMAND界面
    peerCommandWidget := widgets.NewQWidget(nil,0)
    peerCommandWidget.SetLayout(peerCommand)

    //Topic_ORDERER_CONFIG界面
    //从外到里
    ordererConfigWidget := widgets.NewQWidget(nil,0)
    ordererConfigWidgetLayout := widgets.NewQHBoxLayout2(ordererConfigWidget)

    scrollWidget := widgets.NewQScrollArea(ordererConfigWidget)
    scrollWidget.SetWidgetResizable(true)

    scrollAreaWidgetContent := widgets.NewQWidget(nil,0)
    scrollAreaWidgetContent.SetLayout(ordererConfig)//最里层是scrollAreaWidgetContent
    //从里到外，添加
    scrollWidget.SetWidget(scrollAreaWidgetContent)
    ordererConfigWidgetLayout.AddWidget(scrollWidget, 0, 0)
    ordererConfigWidgetLayout.AddItem(widgets.NewQSpacerItem(0,0,widgets.QSizePolicy__Expanding,widgets.QSizePolicy__Expanding))

    //Topic_ORDERER_CHANNEL_CONFIG界面
    ordererChannelConfigWidget := widgets.NewQWidget(nil,0)
    ordererChannelConfigWidget.SetLayout(ordererChannelConfig)
    //Topic_PEER_COMMAND界面
    ordererCommandWidget := widgets.NewQWidget(nil,0)
    ordererCommandWidget.SetLayout(ordererCommand)

    //向stackedtopics添加每个界面
    b.stackedtopics.AddWidget(peerConfigWidget)
    b.stackedtopics.AddWidget(peerCommandWidget)
    b.stackedtopics.AddWidget(ordererConfigWidget)
    b.stackedtopics.AddWidget(ordererChannelConfigWidget)
    b.stackedtopics.AddWidget(ordererCommandWidget)

    b.QGridLayout = widgets.NewQGridLayout2()
    b.AddWidget(b.stackedtopics,0,0,0)
}

func (b *body) getConfigurationData() []byte {
    topicKey := b.topic & mecommon.Topic_MASK
    return b.topics[topicKey].getConfigurationData()
}

type tail struct {
    statusLabel *widgets.QLabel
    resetButton *widgets.QPushButton
    applyButton *widgets.QPushButton
    *widgets.QGridLayout
}

func (t *tail) construct() {
    t.statusLabel = widgets.NewQLabel2("Status:", nil, 0)
    t.resetButton = widgets.NewQPushButton2("重置", nil)
    t.applyButton = widgets.NewQPushButton2("应用", nil)
    t.statusLabel.SetMinimumSize2(450,30)
    t.statusLabel.SetText("status")

    t.resetButton.ConnectClicked( func(bool){ resetButtonClicked() } )
    t.applyButton.ConnectClicked( func(bool){ applyButtonClicked() } )

    t.QGridLayout = widgets.NewQGridLayout2()
    t.QGridLayout.AddWidget3(t.statusLabel,0,0,1,3,0)
    t.QGridLayout.AddWidget3(t.statusLabel,0,0,1,1,0)
    t.QGridLayout.AddWidget3(t.resetButton,0,3,1,1,0)
    t.QGridLayout.AddWidget3(t.applyButton,0,4,1,1,0)
}

func (t *tail) GetStatusLabel() *widgets.QLabel {
    return t.statusLabel
}

type MEConfig struct {
    head *head
    body *body
    tail *tail
    is_constructed bool
    *widgets.QMainWindow
}

func (me *MEConfig) Construct() {
    meconfig = me

    me.QMainWindow = widgets.NewQMainWindow(nil, 0)
    me.QMainWindow.SetWindowTitle("More Easy Config")

    centralWidget := widgets.NewQWidget(me.QMainWindow,0)
    centralWidget.SetMouseTracking(true)
    centralWidgetLayout := widgets.NewQVBoxLayout2(centralWidget)

    me.head = &head{}
    me.body = &body{}
    me.tail = &tail{}

    me.head.construct()
    me.body.construct()
    me.tail.construct()

    centralWidgetLayout.AddLayout(me.head,0)
    centralWidgetLayout.AddLayout(me.body,0)
    centralWidgetLayout.AddLayout(me.tail,0)

    me.QMainWindow.SetCentralWidget(centralWidget)

    me.Show()
    me.is_constructed = true
}

func (me *MEConfig) GetHead() *head {
    return me.head
}

func (me *MEConfig) GetTail() *tail {
    return me.tail
}

func (me *MEConfig) GetConfigurationData() []byte {
    if me.is_constructed == false {
	return nil
    }
    return me.body.getConfigurationData()
}




