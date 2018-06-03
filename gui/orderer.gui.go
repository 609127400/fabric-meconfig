package gui

import (
    "fmt"
    "bytes"
    "encoding/gob"
    "strconv"
    "strings"
    "unsafe"
    "github.com/therecipe/qt/core"
    "github.com/therecipe/qt/gui"
    "github.com/therecipe/qt/widgets"
    "github.com/fabric-meconfig/common/csshare"
)


//组件命名规则：按照yaml文件中，一级一级命名，以_隔开

type generalGroup struct {
    ledgerType *widgets.QComboBox
    listenAddress *widgets.QLineEdit
    listenPort *widgets.QLineEdit
    //tls *widgets.QGroupBox
	tls_Enabled *widgets.QCheckBox
	tls_PrivateKey *widgets.QLineEdit
	tls_Certificate *widgets.QLineEdit
	tls_RootCAs_LineEdit1 *widgets.QLineEdit
	tls_RootCAs_LineEdit2 *widgets.QLineEdit
	tls_RootCAs_LineEdit3 *widgets.QLineEdit
	tls_ClientAuthEnabled *widgets.QCheckBox
	tls_ClientRootCAs *widgets.QLineEdit
    logLevel *widgets.QComboBox
    genesisMethod *widgets.QComboBox
    genesisProfile *widgets.QLineEdit
    genesisFile *widgets.QLineEdit
    localMSPDir *widgets.QLineEdit
    localMSPID *widgets.QLineEdit
    //profile *widgets.QTreeWidget
	profile_Enabled *widgets.QCheckBox
	profile_Address *widgets.QLineEdit
    //bccsp *widgets.QTreeWidget
	bccsp_Default *widgets.QComboBox
	bccsp_SW_Hash *widgets.QComboBox
	bccsp_SW_Security *widgets.QComboBox
	bccsp_SW_FileKeyStore_KeyStore *widgets.QLineEdit
    is_constructed bool
    *widgets.QGroupBox
    //...
}

//每一行末尾表由TEST的为测试用所设置的默认值
func (g *generalGroup) construct() {

    g.ledgerType = widgets.NewQComboBox(nil)
    g.ledgerType.AddItems([]string{ "ram","josn","file", })
    g.ledgerType.SetCurrentIndexDefault(2)
    g.listenAddress = widgets.NewQLineEdit(nil)
    g.listenAddress.SetPlaceholderText("127.0.0.1")
    g.listenAddress.SetText("0.0.0.0") //TEST
    g.listenPort = widgets.NewQLineEdit(nil)
    g.listenPort.SetPlaceholderText("7050")
    g.listenPort.SetText("7050") //TEST
    //tls
    tls := widgets.NewQGroupBox2("安全连接", nil)
    tls.SetWindowTitle("General.TLS")
    tlsLayout := widgets.NewQFormLayout(tls)
	g.tls_Enabled = widgets.NewQCheckBox2("（打勾启用）", nil)
	g.tls_Enabled.SetChecked(true) //TEST
    tlsLayout.AddRow3("启用：",g.tls_Enabled)
	g.tls_PrivateKey = widgets.NewQLineEdit(nil)
	g.tls_PrivateKey.SetPlaceholderText("tls/server.key")
	g.tls_PrivateKey.SetText("/var/hyperledger/orderer/tls/server.key") //TEST
    tlsLayout.AddRow3("私匙路径：",g.tls_PrivateKey)
	g.tls_Certificate = widgets.NewQLineEdit(nil)
	g.tls_Certificate.SetPlaceholderText("tls/server.crt")
	g.tls_Certificate.SetText("/var/hyperledger/orderer/tls/server.crt") //TEST
    tlsLayout.AddRow3("证书：",g.tls_Certificate)
	tls_RootCAs := widgets.NewQGroupBox2("根证书：", nil)
	tls_RootCAsLayout := widgets.NewQFormLayout(tls_RootCAs)
	    g.tls_RootCAs_LineEdit1 = widgets.NewQLineEdit(nil)
	    g.tls_RootCAs_LineEdit1.SetPlaceholderText("tls/ca1.crt")
	    g.tls_RootCAs_LineEdit1.SetText("/var/hyperledger/orderer/tls/ca.crt") //TEST
	tls_RootCAsLayout.AddRow3("路径1：",g.tls_RootCAs_LineEdit1)
	    g.tls_RootCAs_LineEdit2 = widgets.NewQLineEdit(nil)
	    g.tls_RootCAs_LineEdit2.SetPlaceholderText("tls/ca2.crt")
	tls_RootCAsLayout.AddRow3("路径2：",g.tls_RootCAs_LineEdit2)
	    g.tls_RootCAs_LineEdit3 = widgets.NewQLineEdit(nil)
	    g.tls_RootCAs_LineEdit3.SetPlaceholderText("tls/ca3.crt")
	tls_RootCAsLayout.AddRow3("路径3：",g.tls_RootCAs_LineEdit3)
    tlsLayout.AddRow5(tls_RootCAs)
	g.tls_ClientAuthEnabled = widgets.NewQCheckBox2("（打勾启用）", nil)
    tlsLayout.AddRow3("启用客户端认证：",g.tls_ClientAuthEnabled)
	g.tls_ClientRootCAs = widgets.NewQLineEdit(nil)
	g.tls_ClientRootCAs.SetPlaceholderText("tls/client.crt")
    tlsLayout.AddRow3("客户端根证书：",g.tls_ClientRootCAs)
    //
    g.logLevel = widgets.NewQComboBox(nil)
    g.logLevel.AddItems([]string{ "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL" })
    g.genesisMethod = widgets.NewQComboBox(nil)
    g.genesisMethod.AddItems([]string{ "provisional","file" })
    g.genesisMethod.SetCurrentIndexDefault(1) //TEST
    g.genesisProfile = widgets.NewQLineEdit(nil)
    g.genesisProfile.SetPlaceholderText("SampleInsecureSolo")
    g.genesisProfile.SetText("TwoOrgsOrdererGenesis") //TEST
    g.genesisFile = widgets.NewQLineEdit(nil)
    g.genesisFile.SetPlaceholderText("genesisblock")
    g.genesisFile.SetText("/var/hyperledger/orderer/orderer.genesis.block") //TEST
    g.localMSPDir = widgets.NewQLineEdit(nil)
    g.localMSPDir.SetPlaceholderText("msp")
    g.localMSPDir.SetText("/var/hyperledger/orderer/msp") //TEST
    g.localMSPID = widgets.NewQLineEdit(nil)
    g.localMSPID.SetPlaceholderText("DEFAULT")
    g.localMSPID.SetText("OrdererMSP") //TEST
    //profile
    profile := widgets.NewQGroupBox2("在线配置服务", nil)
    profile.SetWindowTitle("General.Profile")
    profileLayout := widgets.NewQFormLayout(profile)
	g.profile_Enabled = widgets.NewQCheckBox2("（打勾启用）", nil)
    profileLayout.AddRow3("启用：",g.profile_Enabled)
	g.profile_Address = widgets.NewQLineEdit(nil)
	g.profile_Address.SetPlaceholderText("0.0.0.0:6060")
    profileLayout.AddRow3("服务地址：",g.profile_Address)
    //bccsp
    bccsp := widgets.NewQGroupBox2("BCCSP", nil)
    bccsp.SetWindowTitle("General.BCCSP")
    bccspLayout := widgets.NewQFormLayout(bccsp)
	g.bccsp_Default = widgets.NewQComboBox(nil)
	g.bccsp_Default.AddItems([]string{ "SW", "PKCS11" })
    bccspLayout.AddRow3("加密服务方式：",g.bccsp_Default)
	bccsp_SW := widgets.NewQGroupBox2("SW", nil)
	bccsp_SW.SetWindowTitle("General.BCCSP.SW")
	bccsp_SW_HashLayout := widgets.NewQFormLayout(bccsp_SW)
	    g.bccsp_SW_Hash = widgets.NewQComboBox(nil)
	    g.bccsp_SW_Hash.AddItems([]string{ "SHA2", "SHA3" })
	bccsp_SW_HashLayout.AddRow3("哈希种类：",g.bccsp_SW_Hash)
	    g.bccsp_SW_Security = widgets.NewQComboBox(nil)
	    g.bccsp_SW_Security.AddItems([]string{ "256", "384" })
	bccsp_SW_HashLayout.AddRow3("哈希长度：",g.bccsp_SW_Security)
	    bccsp_SW_FileKeyStore := widgets.NewQGroupBox2("key文件存储", nil)
	    bccsp_SW_FileKeyStore.SetWindowTitle("General.BCCSP.SW.FileKeyStore")
	    bccsp_SW_FileKeyStoreLayout := widgets.NewQFormLayout(bccsp_SW_FileKeyStore)
		g.bccsp_SW_FileKeyStore_KeyStore = widgets.NewQLineEdit(nil)
	    bccsp_SW_FileKeyStoreLayout.AddRow3("存储路径：",g.bccsp_SW_FileKeyStore_KeyStore)
	bccsp_SW_HashLayout.AddRow5(bccsp_SW_FileKeyStore)
    bccspLayout.AddRow5(bccsp_SW)

    //CIC - CurrentIndexChanged
    //MPE - MousePressEvent
    g.ledgerType.ConnectCurrentIndexChanged(func(index int){ general_ledgerType_CIC(index) })
    //另一种绑定的动作
    //g.ledgerType.ConnectEnterEvent(func(event *core.QEvent){ general_ledgerTypeEnterEvent(event) })
    //g.ledgerType.ConnectLeaveEvent(func(event *core.QEvent){ general_ledgerTypeLeaveEvent(event) })
    g.ledgerType.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_ledgerType_MPE(event) })
    g.listenAddress.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_listenAddress_MPE(event) })
    g.listenPort.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_listenPort_MPE(event) })
    g.tls_Enabled.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_Enabled_MPE(event) })
    g.tls_PrivateKey.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_PrivateKey_MPE(event) })
    g.tls_Certificate.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_Certificate_MPE(event) })
    g.tls_RootCAs_LineEdit1.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_RootCAs_LineEdit1_MPE(event) })
    g.tls_RootCAs_LineEdit2.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_RootCAs_LineEdit2_MPE(event) })
    g.tls_RootCAs_LineEdit3.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_RootCAs_LineEdit3_MPE(event) })
    g.tls_ClientAuthEnabled.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_ClientAuthEnabled_MPE(event) })
    g.tls_ClientRootCAs.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_tls_ClientRootCAs_MPE(event) })
    g.logLevel.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_logLevel_MPE(event) })
    g.genesisMethod.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_genesisMethod_MPE(event) })
    g.genesisProfile.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_genesisProfile_MPE(event) })
    g.genesisFile.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_genesisFile_MPE(event) })
    g.localMSPDir.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_localMSPDir_MPE(event) })
    g.localMSPID.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_localMSPID_MPE(event) })
    g.profile_Enabled.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_profile_Enabled_MPE(event) })
    g.profile_Address.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_profile_Address_MPE(event) })
    g.bccsp_Default.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_bccsp_Default_MPE(event) })
    g.bccsp_SW_Hash.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_bccsp_SW_Hash_MPE(event) })
    g.bccsp_SW_Security.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_bccsp_SW_Security_MPE(event) })
    g.bccsp_SW_FileKeyStore_KeyStore.ConnectMousePressEvent(func(event *gui.QMouseEvent){ general_bccsp_SW_FileKeyStore_KeyStore_MPE(event) })

    g.QGroupBox = widgets.NewQGroupBox2("General", nil)
    layout := widgets.NewQFormLayout(g.QGroupBox)
    layout.AddRow3("账本类型：",g.ledgerType)//LedgerType
    layout.AddRow3("监听地址：",g.listenAddress)//ListenAddress
    layout.AddRow3("监听端口：",g.listenPort)//ListenPort
    layout.AddRow5(tls)//TLS
    layout.AddRow3("日志级别：",g.logLevel)//LogLevel
    layout.AddRow3("创世纪块模式：",g.genesisMethod)//GenesisMethod
    layout.AddRow3("创世纪块配置：",g.genesisProfile)//GenesisProfile
    layout.AddRow3("创世纪块文件名：",g.genesisFile)//GenesisFile
    layout.AddRow3("本地MSP路径：",g.localMSPDir)//LocalMSPDir
    layout.AddRow3("本地MSP标识：",g.localMSPID)//LocalMSPID
    layout.AddRow5(profile)//Profile
    layout.AddRow5(bccsp)//Bccsp

    g.is_constructed = true
}

func (g *generalGroup) getConfigurationData() []byte {
    if g.is_constructed != true { return nil }
    //TODO:检查空值或者给默认值，或在界面提示
    //数组 - xxx 必须和上级对齐或空一格，不能是tab键，
    //且粘贴到别的系统后，查看一下是否符合要求（对齐方式可能会变）
    return []byte(fmt.Sprintf(`
General:
    LedgerType: %s
    ListenAddress: %s
    ListenPort: %s
    TLS:
        Enabled: %s
        PrivateKey: %s
        Certificate: %s
        RootCAs:
	- %s
	- %s
	- %s
        ClientAuthEnabled: %s
        ClientRootCAs:
	- %s
    LogLevel: %s
    GenesisMethod: %s
    GenesisProfile: %s
    GenesisFile: %s
    LocalMSPDir: %s
    LocalMSPID: %s
    Profile:
        Enabled: %s
        Address: %s
    BCCSP:
        Default: %s
        SW:
            Hash: %s
            Security: %s
            FileKeyStore:
                KeyStore: %s
`, //一共23个值
    g.ledgerType.CurrentText(),
    g.listenAddress.Text(),
    g.listenPort.Text(),
    //tls
	strconv.FormatBool(g.tls_Enabled.IsChecked()),
	g.tls_PrivateKey.Text(),
	g.tls_Certificate.Text(),
	g.tls_RootCAs_LineEdit1.Text(),
	g.tls_RootCAs_LineEdit2.Text(),
	g.tls_RootCAs_LineEdit3.Text(),
	strconv.FormatBool(g.tls_ClientAuthEnabled.IsChecked()),
	g.tls_ClientRootCAs.Text(),
    g.logLevel.CurrentText(),
    g.genesisMethod.CurrentText(),
    g.genesisProfile.Text(),
    g.genesisFile.Text(),
    g.localMSPDir.Text(),
    g.localMSPID.Text(),
    //profile
	strconv.FormatBool(g.profile_Enabled.IsChecked()),
	g.profile_Address.Text(),
    //bccsp
	g.bccsp_Default.CurrentText(),
	g.bccsp_SW_Hash.CurrentText(),
	g.bccsp_SW_Security.CurrentText(),
	g.bccsp_SW_FileKeyStore_KeyStore.Text()))

}

type fileLedgerGroup struct {
    location *widgets.QLineEdit
    prefix *widgets.QLineEdit

    is_constructed bool
    *widgets.QGroupBox
}

func (f *fileLedgerGroup) construct() {
    f.location = widgets.NewQLineEdit(nil)
    f.location.SetPlaceholderText("/var/hyperledger/production/orderer")
    f.location.SetText("/var/hyperledger/production/orderer") //TEST
    f.prefix = widgets.NewQLineEdit(nil)
    f.prefix.SetPlaceholderText("hyperledger-fabric-ordererledger")
    f.prefix.SetText("hyperledger-fabric-ordererledger") //TEST

    layout := widgets.NewQFormLayout(nil)
    layout.AddRow3("block账本存储路径：",f.location)//Location
    layout.AddRow3("临时账本文件夹前缀：",f.prefix)//Prefix

    f.QGroupBox = widgets.NewQGroupBox2("FileLedger", nil)
    f.SetLayout(layout)

    f.is_constructed = true
}

func (f *fileLedgerGroup) getConfigurationData() []byte {
    if f.is_constructed != true { return nil }
    //TODO:检查空值或者给默认值
    return []byte(fmt.Sprintf(`
FileLedger:
    Location: %s
    Prefix: %s
`,
f.location.Text(),
f.prefix.Text()))
}

type ramLedgerGroup struct {
    historySize *widgets.QSpinBox

    is_constructed bool
    *widgets.QGroupBox
}

func (r *ramLedgerGroup) construct() {
    r.historySize = widgets.NewQSpinBox(nil)
    r.historySize.SetWindowTitle("RAMLedger.HistorySize")
    r.historySize.SetMinimum(0)
    r.historySize.SetMaximum(1000)
    r.historySize.SetValue(r.historySize.Maximum() / 2)

    layout := widgets.NewQFormLayout(nil)
    layout.AddRow3("账本容量：",r.historySize)//HistorySize

    r.QGroupBox = widgets.NewQGroupBox2("RAMLedger", nil)
    r.SetLayout(layout)

    r.is_constructed = true
}

func (r *ramLedgerGroup) getConfigurationData() []byte {
    if r.is_constructed != true { return nil }
    //TODO:检查空值或者给默认值，或在界面提示
    return []byte(fmt.Sprintf(`
RAMLedger:
    HistorySize: %d
`,r.historySize.Value()))
}

type kafkaGroup struct {
    //retry *widgets.QGroupBox
	retry_ShortInterval *widgets.QSpinBox //ShortInterval: 5s
        retry_ShortTotal *widgets.QSpinBox //ShortTotal: 10m
        retry_LongInterval *widgets.QSpinBox //LongInterval: 5m
        retry_LongTotal *widgets.QSpinBox //LongTotal: 12h
	//retry_NetworkTimeouts *widgets.QGroupBox
	    retry_NetworkTimeouts_DialTimeout *widgets.QSpinBox //DialTimeout: 10s
            retry_NetworkTimeouts_ReadTimeout *widgets.QSpinBox //ReadTimeout: 10s
            retry_NetworkTimeouts_WriteTimeout *widgets.QSpinBox //WriteTimeout: 10s
	//retry_Metadata *widgets.QGroupBox
	    retry_Metadata_RetryBackoff *widgets.QSpinBox //RetryBackoff: 250ms
            retry_Metadata_RetryMax *widgets.QSpinBox //RetryMax: 3
	//retry_Producer *widgets.QGroupBox
	    retry_Producer_RetryBackoff *widgets.QSpinBox //RetryBackoff: 100ms
            retry_Producer_RetryMax *widgets.QSpinBox //RetryMax: 3
	//retry_Consumer *widgets.QGroupBox
            retry_Consumer_RetryBackoff *widgets.QSpinBox //RetryBackoff: 2s
    verbose *widgets.QCheckBox
    //tls *widgets.QGroupBox
	tls_Enabled *widgets.QCheckBox
	//tls_PrivateKey *widgets.QGroupBox
	    tls_PrivateKey_File *widgets.QLineEdit
	//tls_Certificate *widgets.QGroupBox
	    tls_Certificate_File *widgets.QLineEdit
	//tls_RootCAs *widgets.QGroupBox
	    tls_RootCAs_File *widgets.QLineEdit
    version *widgets.QComboBox

    is_constructed bool
    *widgets.QGroupBox
}

func (k *kafkaGroup) construct() {
    //Kafka.Retry
    retry := widgets.NewQGroupBox2("运行容错：",nil)
    retry.SetWindowTitle("Kafka.TLS")
    retryLayout := widgets.NewQFormLayout(retry)
	k.retry_ShortInterval = widgets.NewQSpinBox(nil)
	k.retry_ShortInterval.SetWindowTitle("Kafka.Retry.ShortInterval")
	k.retry_ShortInterval.SetMinimum(3)
	k.retry_ShortInterval.SetMaximum(10)
	k.retry_ShortInterval.SetValue(5)
	retry_ShortIntervalHBox := widgets.NewQHBoxLayout()
	retry_ShortIntervalHBox.AddWidget(k.retry_ShortInterval, 0 ,core.Qt__AlignLeft)
	retry_ShortIntervalHBox.AddWidget(widgets.NewQLabel2("秒", nil, 0), 0 ,core.Qt__AlignLeft)
    retryLayout.AddRow4("短间隔:",retry_ShortIntervalHBox)
	k.retry_ShortTotal = widgets.NewQSpinBox(nil)
	k.retry_ShortTotal.SetWindowTitle("Kafka.Retry.ShortTotal")
	k.retry_ShortTotal.SetMinimum(5)//m
	k.retry_ShortTotal.SetMaximum(20)
	k.retry_ShortTotal.SetValue(10)
	retry_ShortTotalHBox := widgets.NewQHBoxLayout()
	retry_ShortTotalHBox.AddWidget(k.retry_ShortTotal, 0, core.Qt__AlignLeft)
	retry_ShortTotalHBox.AddWidget(widgets.NewQLabel2("分钟", nil, 0), 0, core.Qt__AlignLeft)
    retryLayout.AddRow4("短间隔总时间:",retry_ShortTotalHBox)
	k.retry_LongInterval = widgets.NewQSpinBox(nil)
	k.retry_LongInterval.SetWindowTitle("Kafka.Retry.LongInterval")
	k.retry_LongInterval.SetMinimum(3)
	k.retry_LongInterval.SetMaximum(10)
	k.retry_LongInterval.SetValue(5)
	retry_LongIntervalHBox := widgets.NewQHBoxLayout()
	retry_LongIntervalHBox.AddWidget(k.retry_LongInterval, 0, core.Qt__AlignLeft)
	retry_LongIntervalHBox.AddWidget(widgets.NewQLabel2("分", nil, 0), 0, core.Qt__AlignLeft)
    retryLayout.AddRow4("长间隔:",retry_LongIntervalHBox)
	k.retry_LongTotal = widgets.NewQSpinBox(nil)
	k.retry_LongTotal.SetWindowTitle("Kafka.Retry.LongTotal")
	k.retry_LongTotal.SetMinimum(6)
	k.retry_LongTotal.SetMaximum(24)
	k.retry_LongTotal.SetValue(12)
	retry_LongTotalHBox := widgets.NewQHBoxLayout()
	retry_LongTotalHBox.AddWidget(k.retry_LongTotal, 0, core.Qt__AlignLeft)
	retry_LongTotalHBox.AddWidget(widgets.NewQLabel2("小时", nil, 0), 0, core.Qt__AlignLeft)
    retryLayout.AddRow4("长间隔总时间:",retry_LongTotalHBox)
	retry_NetworkTimeouts := widgets.NewQGroupBox2("网络超时设置：",nil)//NetworkTimeouts
	retry_NetworkTimeoutsLayout := widgets.NewQFormLayout(retry_NetworkTimeouts)
	    k.retry_NetworkTimeouts_DialTimeout = widgets.NewQSpinBox(nil)
	    k.retry_NetworkTimeouts_DialTimeout.SetWindowTitle("Kafka.Retry.NetworkTimeouts.DialTimeout")
	    k.retry_NetworkTimeouts_DialTimeout.SetMinimum(5)
	    k.retry_NetworkTimeouts_DialTimeout.SetMaximum(30)
	    k.retry_NetworkTimeouts_DialTimeout.SetValue(10)
	    retry_NetworkTimeouts_DialTimeoutHBox := widgets.NewQHBoxLayout()
	    retry_NetworkTimeouts_DialTimeoutHBox.AddWidget(k.retry_NetworkTimeouts_DialTimeout, 0, core.Qt__AlignLeft)
	    retry_NetworkTimeouts_DialTimeoutHBox.AddWidget(widgets.NewQLabel2("秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_NetworkTimeoutsLayout.AddRow4("拨号超时:",retry_NetworkTimeouts_DialTimeoutHBox)
	    k.retry_NetworkTimeouts_ReadTimeout = widgets.NewQSpinBox(nil)
	    k.retry_NetworkTimeouts_ReadTimeout.SetWindowTitle("Kafka.Retry.NetworkTimeouts.ReadTimeout")
	    k.retry_NetworkTimeouts_ReadTimeout.SetMinimum(5)
	    k.retry_NetworkTimeouts_ReadTimeout.SetMaximum(30)
	    k.retry_NetworkTimeouts_ReadTimeout.SetValue(10)
	    retry_NetworkTimeouts_ReadTimeoutHBox := widgets.NewQHBoxLayout()
	    retry_NetworkTimeouts_ReadTimeoutHBox.AddWidget(k.retry_NetworkTimeouts_ReadTimeout, 0, core.Qt__AlignLeft)
	    retry_NetworkTimeouts_ReadTimeoutHBox.AddWidget(widgets.NewQLabel2("秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_NetworkTimeoutsLayout.AddRow4("读取超时:",retry_NetworkTimeouts_ReadTimeoutHBox)
	    k.retry_NetworkTimeouts_WriteTimeout = widgets.NewQSpinBox(nil)
	    k.retry_NetworkTimeouts_WriteTimeout.SetWindowTitle("Kafka.Retry.NetworkTimeouts.WriteTimeout")
	    k.retry_NetworkTimeouts_WriteTimeout.SetMinimum(5)
	    k.retry_NetworkTimeouts_WriteTimeout.SetMaximum(30)
	    k.retry_NetworkTimeouts_WriteTimeout.SetValue(10)
	    retry_NetworkTimeouts_WriteTimeoutHBox := widgets.NewQHBoxLayout()
	    retry_NetworkTimeouts_WriteTimeoutHBox.AddWidget(k.retry_NetworkTimeouts_WriteTimeout, 0, core.Qt__AlignLeft)
	    retry_NetworkTimeouts_WriteTimeoutHBox.AddWidget(widgets.NewQLabel2("秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_NetworkTimeoutsLayout.AddRow4("写入超时:",retry_NetworkTimeouts_WriteTimeoutHBox)
    retryLayout.AddRow5(retry_NetworkTimeouts)
	retry_Metadata := widgets.NewQGroupBox2("元数据：",nil)//Metadata
	retry_MetadataLayout := widgets.NewQFormLayout(retry_Metadata)
	    k.retry_Metadata_RetryBackoff = widgets.NewQSpinBox(nil)
	    k.retry_Metadata_RetryBackoff.SetWindowTitle("Kafka.Retry.Metadata.RetryBackoff")
	    k.retry_Metadata_RetryBackoff.SetMinimum(100)//ms
	    k.retry_Metadata_RetryBackoff.SetMaximum(400)
	    k.retry_Metadata_RetryBackoff.SetValue(250)
	    retry_Metadata_RetryBackoffHBox := widgets.NewQHBoxLayout()
	    retry_Metadata_RetryBackoffHBox.AddWidget(k.retry_Metadata_RetryBackoff, 0, core.Qt__AlignLeft)
	    retry_Metadata_RetryBackoffHBox.AddWidget(widgets.NewQLabel2("毫秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_MetadataLayout.AddRow4("RetryBackoff:",retry_Metadata_RetryBackoffHBox)
	    k.retry_Metadata_RetryMax = widgets.NewQSpinBox(nil)
	    k.retry_Metadata_RetryMax.SetWindowTitle("Kafka.Retry.Metadata.RetryMax")
	    k.retry_Metadata_RetryMax.SetMinimum(1)//ms
	    k.retry_Metadata_RetryMax.SetMaximum(5)
	    k.retry_Metadata_RetryMax.SetValue(3)
	    retry_Metadata_RetryMaxHBox := widgets.NewQHBoxLayout()
	    retry_Metadata_RetryMaxHBox.AddWidget(k.retry_Metadata_RetryMax, 0, core.Qt__AlignLeft)
	    retry_Metadata_RetryMaxHBox.AddWidget(widgets.NewQLabel2("次", nil, 0), 0, core.Qt__AlignLeft)
	retry_MetadataLayout.AddRow4("最大尝试次数:",retry_Metadata_RetryMaxHBox)
    retryLayout.AddRow5(retry_Metadata)
	retry_Producer := widgets.NewQGroupBox2("生产者：",nil)//Producer
	retry_ProducerLayout := widgets.NewQFormLayout(retry_Producer)
	    k.retry_Producer_RetryBackoff = widgets.NewQSpinBox(nil)
	    k.retry_Producer_RetryBackoff.SetWindowTitle("Kafka.Retry.Producer.RetryBackoff")
	    k.retry_Producer_RetryBackoff.SetMinimum(50)//ms
	    k.retry_Producer_RetryBackoff.SetMaximum(200)
	    k.retry_Producer_RetryBackoff.SetValue(100)
	    retry_Producer_RetryBackoffHBox := widgets.NewQHBoxLayout()
	    retry_Producer_RetryBackoffHBox.AddWidget(k.retry_Producer_RetryBackoff, 0, core.Qt__AlignLeft)
	    retry_Producer_RetryBackoffHBox.AddWidget(widgets.NewQLabel2("毫秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_ProducerLayout.AddRow4("RetryBackoff:",retry_Producer_RetryBackoffHBox)
	    k.retry_Producer_RetryMax = widgets.NewQSpinBox(nil)
	    k.retry_Producer_RetryMax.SetWindowTitle("Kafka.Retry.Producer.RetryMax")
	    k.retry_Producer_RetryMax.SetMinimum(1)//ms
	    k.retry_Producer_RetryMax.SetMaximum(5)
	    k.retry_Producer_RetryMax.SetValue(3)
	    retry_Producer_RetryMaxHBox := widgets.NewQHBoxLayout()
	    retry_Producer_RetryMaxHBox.AddWidget(k.retry_Producer_RetryMax, 0, core.Qt__AlignLeft)
	    retry_Producer_RetryMaxHBox.AddWidget(widgets.NewQLabel2("次", nil, 0), 0, core.Qt__AlignLeft)
	retry_ProducerLayout.AddRow4("最大尝试次数:",retry_Producer_RetryMaxHBox)
    retryLayout.AddRow5(retry_Producer)
	retry_Consumer := widgets.NewQGroupBox2("消费者：",nil)//Consumer
	retry_ConsumerLayout := widgets.NewQFormLayout(retry_Consumer)
	    k.retry_Consumer_RetryBackoff = widgets.NewQSpinBox(nil)
	    k.retry_Consumer_RetryBackoff.SetWindowTitle("Kafka.Retry.Consumer.RetryBackoff")
	    k.retry_Consumer_RetryBackoff.SetMinimum(1500)//ms
	    k.retry_Consumer_RetryBackoff.SetMaximum(5000)
	    k.retry_Consumer_RetryBackoff.SetValue(2000)
	    retry_Consumer_RetryBackoffHBox := widgets.NewQHBoxLayout()
	    retry_Consumer_RetryBackoffHBox.AddWidget(k.retry_Consumer_RetryBackoff, 0, core.Qt__AlignLeft)
	    retry_Consumer_RetryBackoffHBox.AddWidget(widgets.NewQLabel2("毫秒", nil, 0), 0, core.Qt__AlignLeft)
	retry_ConsumerLayout.AddRow4("RetryBackoff:",retry_Consumer_RetryBackoffHBox)
    retryLayout.AddRow5(retry_Consumer)
    //Kafka.Verbose
    k.verbose = widgets.NewQCheckBox2("（打勾启用）", nil)

    //Kafka.TLS
    tls := widgets.NewQGroupBox2("安全连接：",nil)
    tls.SetWindowTitle("Kafka.TLS")
    tlsLayout := widgets.NewQFormLayout(tls)
	k.tls_Enabled = widgets.NewQCheckBox2("（打勾启用）", nil)
    tlsLayout.AddRow3("启用：",k.tls_Enabled)
	tls_PrivateKey := widgets.NewQGroupBox2("私匙：",nil)
	tls_PrivateKeyLayout := widgets.NewQFormLayout(tls_PrivateKey)
	    k.tls_PrivateKey_File = widgets.NewQLineEdit(nil)
	    k.tls_PrivateKey_File.SetPlaceholderText("path/to/PrivateKey")
	tls_PrivateKeyLayout.AddRow3("私匙路径",k.tls_PrivateKey_File)
    tlsLayout.AddRow5(tls_PrivateKey)
	tls_Certificate := widgets.NewQGroupBox2("证书：",nil)
	tls_CertificateLayout := widgets.NewQFormLayout(tls_Certificate)
	    k.tls_Certificate_File = widgets.NewQLineEdit(nil)
	    k.tls_Certificate_File.SetPlaceholderText("path/to/Certificate")
	tls_CertificateLayout.AddRow3("证书路径",k.tls_Certificate_File)
    tlsLayout.AddRow5(tls_Certificate)
	tls_RootCAs := widgets.NewQGroupBox2("根证书：",nil)
	tls_RootCAsLayout := widgets.NewQFormLayout(tls_RootCAs)
	    k.tls_RootCAs_File = widgets.NewQLineEdit(nil)
	    k.tls_RootCAs_File.SetPlaceholderText("path/to/RootCAs")
	tls_RootCAsLayout.AddRow3("根证书路径",k.tls_RootCAs_File)
    tlsLayout.AddRow5(tls_RootCAs)
    //Kafka.Version
    k.version = widgets.NewQComboBox(nil)
    k.version.AddItems([]string{ "0.8.2.0","0.8.2.1","0.8.2.2","0.9.0.0","0.9.0.1","0.10.0.0","0.10.0.1","0.10.1.0" })

    k.QGroupBox = widgets.NewQGroupBox2("Kafka", nil)
    layout := widgets.NewQFormLayout(k.QGroupBox)
    layout.AddRow5(retry)
    layout.AddRow3("日志记录：",k.verbose)
    layout.AddRow5(tls)
    layout.AddRow3("版本：",k.version)

    k.is_constructed = true
}

func (k *kafkaGroup) getConfigurationData() []byte {
    if k.is_constructed != true { return nil }
    //TODO:检查空值或者给默认值，或在界面提示
    return []byte(fmt.Sprintf(`
Kafka:
    Retry:
        ShortInterval: %ds
        ShortTotal: %dm
        LongInterval: %dm
        LongTotal: %dh
        NetworkTimeouts:
            DialTimeout: %ds
            ReadTimeout: %ds
            WriteTimeout: %ds
        Metadata:
            RetryBackoff: %dms
            RetryMax: %d
        Producer:
            RetryBackoff: %dms
            RetryMax: %d
        Consumer:
            RetryBackoff: %ds
    Verbose: %s
    TLS:
      Enabled: %s
      PrivateKey:
        File: %s
      Certificate:
        File: %s
      RootCAs:
        File: %s
    Version: %s
`,//共18个值
    //retry *widgets.QGroupBox
	k.retry_ShortInterval.Value(), //ShortInterval: 5s
        k.retry_ShortTotal.Value(), //ShortTotal: 10m
        k.retry_LongInterval.Value(), //LongInterval: 5m
        k.retry_LongTotal.Value(), //LongTotal: 12h
	//retry_NetworkTimeouts *widgets.QGroupBox
	    k.retry_NetworkTimeouts_DialTimeout.Value(), //DialTimeout: 10s
            k.retry_NetworkTimeouts_ReadTimeout.Value(), //ReadTimeout: 10s
            k.retry_NetworkTimeouts_WriteTimeout.Value(), //WriteTimeout: 10s
	//retry_Metadata *widgets.QGroupBox
	    k.retry_Metadata_RetryBackoff.Value(), //RetryBackoff: 250ms
            k.retry_Metadata_RetryMax.Value(), //RetryMax: 3
	//retry_Producer *widgets.QGroupBox
	    k.retry_Producer_RetryBackoff.Value(), //RetryBackoff: 100ms
            k.retry_Producer_RetryMax.Value(), //RetryMax: 3
	//retry_Consumer *widgets.QGroupBox
            k.retry_Consumer_RetryBackoff.Value(), //RetryBackoff: 2s
	strconv.FormatBool(k.verbose.IsChecked()),
    //tls *widgets.QGroupBox
	strconv.FormatBool(k.tls_Enabled.IsChecked()),
	//tls_PrivateKey *widgets.QGroupBox
	    k.tls_PrivateKey_File.Text(),
	//tls_Certificate *widgets.QGroupBox
	    k.tls_Certificate_File.Text(),
	//tls_RootCAs *widgets.QGroupBox
	    k.tls_RootCAs_File.Text(),
    k.version.CurrentText()))
}

type ordererConfig struct {
    general *generalGroup
    fileLedger *fileLedgerGroup
    ramLedger *ramLedgerGroup
    kafka *kafkaGroup

    is_constructed bool
    *widgets.QVBoxLayout
}

func (o *ordererConfig) construct() {
    o.general    = &generalGroup{}
    o.fileLedger = &fileLedgerGroup{}
    o.ramLedger  = &ramLedgerGroup{}
    o.kafka      = &kafkaGroup{}

    o.general.construct()
    o.fileLedger.construct()
    o.ramLedger.construct()
    o.kafka.construct()

    o.QVBoxLayout = widgets.NewQVBoxLayout()
    o.AddWidget(o.general,0,0)
    o.AddWidget(o.fileLedger,0,0)
    o.AddWidget(o.ramLedger,0,0)
    o.AddWidget(o.kafka,0,0)

    o.is_constructed = true
}

func (o *ordererConfig) getConfigurationData() []byte {
    if o.is_constructed != true { return nil }
    general    := o.general.getConfigurationData()
    fileLedger := o.fileLedger.getConfigurationData()
    ramLedger  := o.ramLedger.getConfigurationData()
    kafka      := o.kafka.getConfigurationData()

    all := make([][]byte, 4)
    all[0] = general
    all[1] = fileLedger
    all[2] = ramLedger
    all[3] = kafka

    return bytes.Join(all, []byte(""))
}

type functionGroup struct {
    listChannelInfo *widgets.QPushButton
    addNewOrg *widgets.QPushButton
    modifyCurrentOrg *widgets.QPushButton
    deleteCurrentOrg *widgets.QPushButton
    //当服务端是容器部署时，这里是容器名，若是物理机部署时，这里是物理机的HOSTNAME
    idComboBox *widgets.QComboBox
    ordererIPLineEdit *widgets.QLineEdit
    caFilePathLineEdit *widgets.QLineEdit

    is_constructed bool
    *widgets.QGroupBox
}

//每一行末尾表由TEST的为测试用所设置的默认值
func (f *functionGroup) construct() {

    f.listChannelInfo = widgets.NewQPushButton2("通道信息", nil)
    f.addNewOrg = widgets.NewQPushButton2("添加组织", nil)
    f.modifyCurrentOrg = widgets.NewQPushButton2("修改组织", nil)
    f.deleteCurrentOrg = widgets.NewQPushButton2("删除组织", nil)
    funLayout := widgets.NewQHBoxLayout()
    funLayout.AddWidget(f.listChannelInfo,0,0)
    funLayout.AddWidget(f.addNewOrg,0,0)
    funLayout.AddWidget(f.modifyCurrentOrg,0,0)
    funLayout.AddWidget(f.deleteCurrentOrg,0,0)

    label := widgets.NewQLabel2("操作所需信息:", nil, 0)
    f.idComboBox = widgets.NewQComboBox(nil)
    f.idComboBox.AddItems([]string{"Peer节点"})
    f.idComboBox.SetCurrentIndex(0)
    f.ordererIPLineEdit = widgets.NewQLineEdit(nil)
    f.ordererIPLineEdit.SetPlaceholderText("OrdererIP:_._._._:port")
    f.ordererIPLineEdit.SetText("orderer.example.com:7050") //TEST
    f.caFilePathLineEdit = widgets.NewQLineEdit(nil)
    f.caFilePathLineEdit.SetPlaceholderText("节点所持Orderer的TLS CA证书路径")
    f.caFilePathLineEdit.SetText("/etc/hyperledger/fabric/tls/tlsca.example.com-cert.pem") //TEST
    infoLayout := widgets.NewQHBoxLayout()
    infoLayout.AddWidget(label,1,0)
    infoLayout.AddWidget(f.idComboBox,1,0)
    infoLayout.AddWidget(f.ordererIPLineEdit,2,0)
    infoLayout.AddWidget(f.caFilePathLineEdit,4,0)

    f.listChannelInfo.ConnectClicked(func(_ bool) { listChannelInfoButtonClick() })
    f.addNewOrg.ConnectClicked(func(_ bool) { addNewOrgButtonClick() })
    f.modifyCurrentOrg.ConnectClicked(func(_ bool) { modifyCurrentOrgButtonClick() })
    f.deleteCurrentOrg.ConnectClicked(func(_ bool) { deleteCurrentOrgButtonClick() })
    f.idComboBox.ConnectCurrentIndexChanged(func(index int) { idComboBoxCurrentIndexChanged(index) })

    f.QGroupBox = widgets.NewQGroupBox2("功能", nil)
    layout := widgets.NewQVBoxLayout2(f.QGroupBox)
    layout.AddLayout(funLayout, 2)
    layout.AddLayout(infoLayout, 1)

    f.is_constructed = true
}

//通道信息对应的stack
type listAndDisplayGroup struct {
    listBasicInfoButton *widgets.QPushButton
    listDetailInfoButton *widgets.QPushButton

    displayBasicInfo *widgets.QTableWidget
    displayBasicInfoColumn int
    displayDetailInfo *widgets.QTextBrowser

    is_constructed bool
    *widgets.QGroupBox
}

func (ld *listAndDisplayGroup) construct() {
    //最后一列 所属的Channel的格式
    //若是正常的多个channelID，每个channelID以','分割，最后以'(*^_^*)'后缀
    ld.listBasicInfoButton = widgets.NewQPushButton2("基本信息", nil)
    ld.listBasicInfoButton.SetMaximumSize2(65,25)
    ld.displayBasicInfo = widgets.NewQTableWidget(nil)
    ld.displayBasicInfoColumn = 4
    ld.displayBasicInfo.SetColumnCount(ld.displayBasicInfoColumn)
    ld.displayBasicInfo.SetHorizontalHeaderLabels([]string{"节点名", "容器ID", "开启TLS", "所属Channel"})
    ld.displayBasicInfo.HorizontalHeader().SetStretchLastSection(true)
    leftLayout := widgets.NewQVBoxLayout()
    leftLayout.AddWidget(ld.listBasicInfoButton,1,core.Qt__AlignLeft)
    leftLayout.AddWidget(ld.displayBasicInfo,8,0)
    leftLayout.SetSpacing(5)

    ld.listDetailInfoButton = widgets.NewQPushButton2("详细信息", nil)
    ld.listDetailInfoButton.SetMaximumSize2(65,25)
    ld.displayDetailInfo = widgets.NewQTextBrowser(nil)
    rightLayout := widgets.NewQVBoxLayout()
    rightLayout.AddWidget(ld.listDetailInfoButton,1,core.Qt__AlignLeft)
    rightLayout.AddWidget(ld.displayDetailInfo,8,0)
    rightLayout.SetSpacing(5)

    ld.listBasicInfoButton.ConnectClicked(func(_ bool) {
	ld.listDetailInfoButton.SetEnabled(false)
	listChannelBasicInfoButtonClick()
	ld.listDetailInfoButton.SetEnabled(true)
    })
    ld.listDetailInfoButton.ConnectClicked(func(_ bool) { listChannelDetailInfoButtonClick() })

    ld.QGroupBox = widgets.NewQGroupBox2("信息", nil)
    layout := widgets.NewQHBoxLayout2(ld.QGroupBox)
    layout.AddLayout(leftLayout, 3)
    layout.AddLayout(rightLayout, 5)

    ld.is_constructed = true
}

type addOrgGroup struct {
    //签名节点
    signNodeIP *widgets.QLineEdit
    signNodeContainerID *widgets.QLineEdit
    //FCP - fabric_cfg_path
    signNodeFCP *widgets.QLineEdit
    signNodeAddOne *widgets.QPushButton
    signNodeLayout *widgets.QVBoxLayout
    signNodeNum int

    channelID *widgets.QComboBox
    orgName *widgets.QLineEdit
    orgID *widgets.QLineEdit
    orgMSPDir *widgets.QLineEdit
    //xx.xx.xx.xx:port
    orgAnchorPeer *widgets.QLineEdit
    orgAnchorPeerAddOne *widgets.QPushButton
    orgAnchorPeersLayout *widgets.QVBoxLayout
    orgAnchorPeerNum int

    orgDomain *widgets.QLineEdit
    //Spec
    //三个控件为一套，均放在一个VBox中，然后再添加到orgSpecsLayout中
    orgSpecHostname *widgets.QLineEdit
    orgSpecCommonName *widgets.QLineEdit
    orgSpecSANS *widgets.QLineEdit
    orgSpecAddOne *widgets.QPushButton
    orgSpecsLayout *widgets.QVBoxLayout
    orgSpecNum int

    orgTemplateCount *widgets.QSpinBox
    orgTemplateStart *widgets.QSpinBox
    orgTemplateHostname *widgets.QLineEdit //{{.Prefix}}{{.Index}}
    orgUsersCount *widgets.QSpinBox

    is_constructed bool
    *widgets.QGroupBox
}

func (ao *addOrgGroup) construct() {
    ao.signNodeIP = widgets.NewQLineEdit(nil)
    ao.signNodeIP.SetObjectName("SignNodeIP1")
    ao.signNodeIP.SetPlaceholderText("签名节点IP")
    ao.orgMSPDir.SetText("127.0.0.1:10000")//TEST
    ao.signNodeContainerID = widgets.NewQLineEdit(nil)
    ao.signNodeContainerID.SetObjectName("SignNodeContainerID1")
    ao.signNodeContainerID.SetPlaceholderText("签名节点容器ID")
    ao.signNodeFCP = widgets.NewQLineEdit(nil)
    ao.signNodeFCP.SetObjectName("SignNodeConfigPath1")
    ao.signNodeFCP.SetPlaceholderText("签名节点配置路径(确保MSP与core.yaml均在此目录下)，若为空，则默认取FABRIC_CFG_PATH环境变量值")
    ao.signNodeAddOne = widgets.NewQPushButton2("+", nil)
    signNodeFirstLayout := widgets.NewQHBoxLayout()
    signNodeFirstLayout.AddWidget(ao.signNodeIP, 1, 0)
    signNodeFirstLayout.AddWidget(ao.signNodeContainerID, 1, 0)
    signNodeFirstLayout.AddWidget(ao.signNodeFCP, 2, 0)
    signNodeFirstLayout.AddWidget(ao.signNodeAddOne, 0, 0)
    ao.signNodeLayout = widgets.NewQVBoxLayout()
    ao.signNodeLayout.AddLayout(signNodeFirstLayout, 0)
    ao.signNodeNum = 1
    //configtx.yaml
    ao.orgName = widgets.NewQLineEdit(nil)
    ao.orgName.SetPlaceholderText("Org3")
    ao.orgName.SetText("Org3")//TEST
    ao.orgID = widgets.NewQLineEdit(nil)
    ao.orgID.SetPlaceholderText("Org3MSP")
    ao.orgID.SetText("Org3MSP")//TEST
    ao.orgMSPDir = widgets.NewQLineEdit(nil)
    ao.orgMSPDir.SetPlaceholderText("crypto-config/peerOrganizations/org3.example.com/msp")
    ao.orgMSPDir.SetText("crypto-config/peerOrganizations/org3.example.com/msp")//TEST
    ao.orgAnchorPeer = widgets.NewQLineEdit(nil)
    ao.orgAnchorPeer.SetObjectName("AnchorPeer1")
    ao.orgAnchorPeer.SetPlaceholderText("peer0.org3.example.com:7051")
    ao.orgAnchorPeer.SetText("peer0.org3.example.com:7051")//TEST
    ao.orgAnchorPeerAddOne = widgets.NewQPushButton2("+", nil)
    anchorPeerFirstLayout := widgets.NewQHBoxLayout()
    anchorPeerFirstLayout.AddWidget(ao.orgAnchorPeer, 0, 0)
    anchorPeerFirstLayout.AddWidget(ao.orgAnchorPeerAddOne, 0, 0)
    ao.orgAnchorPeersLayout = widgets.NewQVBoxLayout()
    ao.orgAnchorPeersLayout.AddLayout(anchorPeerFirstLayout, 0)
    ao.channelID = widgets.NewQComboBox(nil)
    ao.orgAnchorPeerNum = 1

    //crypto.yaml
    ao.orgDomain = widgets.NewQLineEdit(nil)
    ao.orgDomain.SetPlaceholderText("org3.example.com")
    ao.orgDomain.SetText("org3.example.com")//TEST

    ao.orgSpecHostname = widgets.NewQLineEdit(nil)
    ao.orgSpecHostname.SetObjectName("SpecHostName1")
    ao.orgSpecHostname.SetPlaceholderText("customName.org3.example.com")
    ao.orgSpecHostname.SetText("customName.org3.example.com")//TEST
    ao.orgSpecAddOne = widgets.NewQPushButton2("+", nil)
    specFirstLayout := widgets.NewQHBoxLayout()
    specFirstLayout.AddWidget(ao.orgSpecHostname, 0, 0)
    specFirstLayout.AddWidget(ao.orgSpecAddOne, 0, 0)
    ao.orgSpecCommonName = widgets.NewQLineEdit(nil)
    ao.orgSpecCommonName.SetObjectName("SpecCommonName1")
    ao.orgSpecCommonName.SetPlaceholderText("即证书中CN字段，可定义模板，也可为实际的名称，默认模板 '{{.Hostname}}.{{.Domain}}'）")
    ao.orgSpecCommonName.SetText("")//TEST
    ao.orgSpecSANS = widgets.NewQLineEdit(nil)
    ao.orgSpecSANS.SetObjectName("SpecSANS1")
    ao.orgSpecSANS.SetPlaceholderText("默认为空")
    orgChildLayout := widgets.NewQFormLayout(nil)
    orgChildLayout.AddRow3("", nil)
    orgChildLayout.AddRow4("主机名", specFirstLayout)
    orgChildLayout.AddRow3("CN", ao.orgSpecCommonName)
    orgChildLayout.AddRow3("SANS", ao.orgSpecSANS)
    orgChildLayout.AddRow3("-----------", nil)
    ao.orgSpecsLayout = widgets.NewQVBoxLayout()
    ao.orgSpecsLayout.AddLayout(orgChildLayout, 0)
    ao.orgSpecNum = 1

    ao.orgTemplateCount = widgets.NewQSpinBox(nil)
    ao.orgTemplateCount.SetMinimum(0)
    ao.orgTemplateCount.SetMaximum(100)
    ao.orgTemplateStart = widgets.NewQSpinBox(nil)
    ao.orgTemplateStart.SetMinimum(0)
    ao.orgTemplateStart.SetMaximum(100)
    ao.orgTemplateHostname = widgets.NewQLineEdit(nil)
    ao.orgTemplateHostname.SetPlaceholderText("{{.Prefix}}{{.Index}}")
    ao.orgTemplateHostname.SetText("{{.Prefix}}{{.Index}}")//TEST
    ao.orgUsersCount = widgets.NewQSpinBox(nil)
    ao.orgUsersCount.SetMinimum(0)
    ao.orgUsersCount.SetMaximum(100)

    ao.signNodeAddOne.ConnectClicked(func(_ bool) { addOneSignNodeButtonClick(ao) })
    ao.orgAnchorPeerAddOne.ConnectClicked(func(_ bool) { addOneAnchorPeerButtonClick(ao) })
    ao.orgSpecAddOne.ConnectClicked(func(_ bool) { addOneSpecButtonClick(ao) })

    ao.QGroupBox = widgets.NewQGroupBox2("添加组织信息", nil)
    layout := widgets.NewQVBoxLayout2(ao.QGroupBox)

    contentLayout := widgets.NewQFormLayout(nil)
    contentLayout.AddRow4("签名节点", ao.signNodeLayout)
    contentLayout.AddRow3("------------------------------", nil)
    contentLayout.AddRow3("组织名:", ao.orgName)
    contentLayout.AddRow3("组织ID:", ao.orgID)
    contentLayout.AddRow3("组织MSP路径:", ao.orgMSPDir)
    contentLayout.AddRow4("组织锚点:", ao.orgAnchorPeersLayout)
    contentLayout.AddRow3("所属Channel:", ao.channelID)
    contentLayout.AddRow3("------------------------------", nil)
    contentLayout.AddRow3("组织域名:", ao.orgDomain)
    contentLayout.AddRow4("个性化定义节点", ao.orgSpecsLayout)
    contentLayout.AddRow3("模板定义节点", nil)
    contentLayout.AddRow3("    节点总数:", ao.orgTemplateCount)
    contentLayout.AddRow3("    起始后缀:", ao.orgTemplateStart)
    contentLayout.AddRow3("    节点主机名模板:", ao.orgTemplateHostname)
    contentLayout.AddRow3("    组织普通用户数:", ao.orgUsersCount)

    scrollAreaWidgetContent := widgets.NewQWidget(nil,0)
    scrollAreaWidgetContent.SetLayout(contentLayout)

    scrollWidget := widgets.NewQScrollArea(nil)
    scrollWidget.SetWidgetResizable(true)
    scrollWidget.SetWidget(scrollAreaWidgetContent)

    layout.AddWidget(scrollWidget, 0, 0)

    ao.is_constructed = true
}

func (ao *addOrgGroup) getConfigurationData() []byte {
    if ao.is_constructed == false {
	return nil
    }

    if ordererCC.function.idComboBox.CurrentIndex() < 1 ||
       ordererCC.function.ordererIPLineEdit.Text() == "" ||
       ao.orgName.Text() == "" || ao.orgID.Text() == ""  ||
       ao.orgMSPDir.Text() == "" || ao.orgDomain.Text() == "" ||
       ao.channelID.CurrentText() == "" || ao.orgTemplateCount.Value() == 0 {
	return nil
    }

    var signnode, configtx, crypto string
    var obj *core.QObject
    var ptr unsafe.Pointer
    var tlsEnabled bool
    infos := make(map[string]string)

    for i := 1; i <= ao.signNodeNum; i++ {
	obj = ao.FindChild(fmt.Sprintf("SignNodeIP%d", i), 1)
	ptr = obj.Pointer()
	ip := widgets.NewQLineEditFromPointer(ptr).Text()
	if ip == "" {
	    continue
	}
	obj = ao.FindChild(fmt.Sprintf("SignNodeContainerID%d", i), 1)
	ptr = obj.Pointer()
	containerid := widgets.NewQLineEditFromPointer(ptr).Text()
	obj = ao.FindChild(fmt.Sprintf("SignNodeConfigPath%d", i), 1)
	ptr = obj.Pointer()
	msppath := widgets.NewQLineEditFromPointer(ptr).Text()
	signnode = ip + csshare.SEPARATOR + containerid + csshare.SEPARATOR + msppath
	infos[fmt.Sprintf("%s%d", csshare.AddOrgSignNode, i)] = signnode
    }
    infos[csshare.AddOrgSignNodeNum] = fmt.Sprintf("%d", ao.signNodeNum)

    //idComboBox和displayBasicInfo信息顺序一致，所以直接定位到row行的第2列，判断该节点是否开启了TLS
    row := ordererCC.function.idComboBox.CurrentIndex() - 1
    //logger.Printf("row-%d, text:[%s], ==[%v]", row, ordererCC.listAndDisplay.displayBasicInfo.Item(row, 2).Text(), ordererCC.listAndDisplay.displayBasicInfo.Item(row, 2).Text()=="true")
    if ordererCC.listAndDisplay.displayBasicInfo.Item(row, 2).Text() == "true" {
	if ordererCC.function.caFilePathLineEdit.Text() == "" {
	    return nil
	}
	//logger.Println("进来了")
	tlsEnabled = true
    }

    configtx = fmt.Sprintf(`
Organizations:
    - &%s
        Name: %s
        ID: %s
        MSPDir: %s`, ao.orgName.Text(), ao.orgName.Text(), ao.orgID.Text(), ao.orgMSPDir.Text())

    for i := 1; i <= ao.orgAnchorPeerNum; i++ {
	//与construct中的SetObjectName对应
	obj = ao.FindChild(fmt.Sprintf("AnchorPeer%d", i), 1)
	ptr = obj.Pointer()
	ip := widgets.NewQLineEditFromPointer(ptr).Text()
	if ip == "" {
	    continue
	}
	ipSlice := strings.Split(ip, ":")
	if len(ipSlice) != 2 {
	    return nil
	}
	configtx += fmt.Sprintf(
`
        AnchorPeers:
            - Host: %s
              Port: %s`,ipSlice[0], ipSlice[1])
    }
    //TODO:Template中也有SANS数组字段
    //所有值是模板的字段要注意加引号
    crypto = fmt.Sprintf(`
PeerOrgs:
  - Name: %s
    Domain: %s
    Template:
      Count: %d
      Start: %d
      Hostname: "%s"
    Users:
      Count: %d
    Specs:`, ao.orgName.Text(), ao.orgDomain.Text(), ao.orgTemplateCount.Value(),
ao.orgTemplateStart.Value(), ao.orgTemplateHostname.Text(), ao.orgUsersCount.Value())

    for i := 1; i <= ao.orgSpecNum; i++ {
	//与construct中的SetObjectName对应
	obj = ao.FindChild(fmt.Sprintf("SpecHostName%d", i), 1)
	ptr = obj.Pointer()
	hn := widgets.NewQLineEditFromPointer(ptr).Text()
	obj = ao.FindChild(fmt.Sprintf("SpecCommonName%d", i), 1)
	ptr = obj.Pointer()
	cn := widgets.NewQLineEditFromPointer(ptr).Text()
	obj = ao.FindChild(fmt.Sprintf("SpecSANS%d", i), 1)
	ptr = obj.Pointer()
	sans := widgets.NewQLineEditFromPointer(ptr).Text()
	//此三个组件中若填写，只有hn是必填，因此若hn为空，则默认为未设置
	if hn == "" {
	    continue
	}
	crypto += fmt.Sprintf(
`
      - Hostname: %s
        CommonName: "%s"`, hn, cn)
	//TODO:Specs的SANS其实是一个数组类型的，这里只放一个
	//数组不能为空，不能是 - ""
	if sans != "" {
	    crypto += fmt.Sprintf(
`
	SANS:
	  - "%s"`, sans)
	}
    }

    infos[csshare.AddOrgOrgName]     = ao.orgName.Text()
    infos[csshare.AddOrgConfigtx]    = configtx
    infos[csshare.AddOrgCrypto]      = crypto
    infos[csshare.AddOrgContainerID] = ordererCC.listAndDisplay.displayBasicInfo.Item(row, 1).Text()
    infos[csshare.AddOrgOrdererIP]   = ordererCC.function.ordererIPLineEdit.Text()
    infos[csshare.AddOrgChannelID]   = ao.channelID.CurrentText()
    if tlsEnabled {
	infos[csshare.AddOrgTLSCAPath] = ordererCC.function.caFilePathLineEdit.Text()
    }

    buffer := &bytes.Buffer{}
    err := gob.NewEncoder(buffer).Encode(infos)
    if err != nil {
	logger.Printf("gob Encode(infos) failed: %s\n", err)
	return nil
    }

    return buffer.Bytes()
}

var ordererCC *ordererChannelConfig

type ordererChannelConfig struct {
    function *functionGroup
	listAndDisplay *listAndDisplayGroup
	addOrg *addOrgGroup
    stackedConfigAndDisplay *widgets.QStackedWidget

    is_constructed bool
    *widgets.QVBoxLayout
}

func (occ *ordererChannelConfig) construct() {
    //ordererCC在addOrg中有使用，所以须在addOrg初始化之前赋值
    ordererCC = occ
    occ.function = &functionGroup{}
    occ.listAndDisplay = &listAndDisplayGroup{}
    occ.addOrg = &addOrgGroup{}

    occ.function.construct()
	occ.listAndDisplay.construct()
	//addOrg必须在listAndDisplay初始化之后再初始化，因为addOrg有用到listAndDisplay中的组件
	occ.addOrg.construct()

    occ.stackedConfigAndDisplay = widgets.NewQStackedWidget(nil)
    occ.stackedConfigAndDisplay.AddWidget(occ.listAndDisplay)//0
    occ.stackedConfigAndDisplay.AddWidget(occ.addOrg)//1

    occ.QVBoxLayout = widgets.NewQVBoxLayout()
    occ.AddWidget(occ.function, 1, 0)
    occ.AddWidget(occ.stackedConfigAndDisplay, 5, 0)

    occ.is_constructed = true
}

func (occ *ordererChannelConfig) getConfigurationData() []byte {
    if occ.is_constructed == false {
	return nil
    }
    switch occ.stackedConfigAndDisplay.CurrentIndex() {
    case 0:
	//do nothing
	return nil
    case 1:
	return occ.addOrg.getConfigurationData()
    }
    return nil
}

type ordererCommand struct {
    label *widgets.QLabel

    is_constructed bool
    *widgets.QVBoxLayout
}

func (p *ordererCommand) construct() {
    p.label = widgets.NewQLabel2("O R D E R E R - C O M M A N D",nil,0)
    p.QVBoxLayout = widgets.NewQVBoxLayout()
    p.AddWidget(p.label,0,0)

    p.is_constructed = true
}

func (p *ordererCommand) getConfigurationData() []byte {
    return nil
}


