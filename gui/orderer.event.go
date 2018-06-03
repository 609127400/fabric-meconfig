

package gui

import (
    "fmt"
    "bytes"
    "strings"
    "encoding/gob"
    "encoding/base64"

    "github.com/therecipe/qt/widgets"
    "github.com/therecipe/qt/gui"
    "github.com/tidwall/gjson"

    //fcb "github.com/hyperledger/fabric/protos/common"

    "github.com/fabric-meconfig/common/meclient"
    "github.com/fabric-meconfig/common/protos"
    "github.com/fabric-meconfig/common/csshare"
)








func general_ledgerType_CIC(index int) {
    switch(index){
    case 0:
	meconfig.head.explainBowser.SetText("An in-memory ledger whose contents are lost on restart.")
    case 1:
	meconfig.head.explainBowser.SetText("A simple file ledger that writes blocks to disk in JSON format.")
    case 2:
	meconfig.head.explainBowser.SetText("A production file-based ledger.")
    default:
	meconfig.head.explainBowser.SetText("A production file-based ledger.")
    }
}

/*
//另一种绑定的动作
func generalTypeEnterEvent(event *core.QEvent) {
    meconfig.head.explainBowser.SetText("Ledger Type: The ledger type to provide to the orderer.")
}
func cleanExplainLeaveEvent(event *core.QEvent) {
    meconfig.head.explainBowser.SetText("")
}
*/

func general_ledgerType_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer节点使用的账本类型，分为文本/json/内存三种类型。")
}

func general_listenAddress_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer程序监听的所在容器或物理机的地址，一般为Orderer所在本机或容器地址0.0.0.0。设置该值，会将Orderer所在的物理机或容器的环境变量ORDERER_GENERAL_LISTENADDRESS的值覆盖")
}

func general_listenPort_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer程序监听的所在容器或物理机的端口，如7050")
}

func general_tls_Enabled_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Peer节点与Orderer节点进行GRPC连接时，是否开启TLS安全连接，开启后，会使用[私匙路径]所指向的私匙对来自peer的连接的签名进行验证，设置该值后，会将Orderer所在的物理机或容器的环境变量ORDERER_GENERAL_TLS_ENABLED的值覆盖")
}

func general_tls_PrivateKey_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer节点开启TLS验证时，会使用该路径下的私匙对Peer节点的连接进行安全验证，值如/var/hyperledger/orderer/tls/server.key。设置该值后，会将Orderer所在物理机或容器的环境变量ORDERER_GENERAL_TLS_PRIVATEKEY的值覆盖")
}

func general_tls_Certificate_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("的环境变量ORDERER_GENERAL_TLS_CERTIFICATE的值覆盖")
}

func general_tls_RootCAs_LineEdit1_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer验证Peer连接时所使用的客户端的根证书路径。该路径可以使用[cryptogen generate --config=./crypto-config.yaml]命令生成的Orderer组织中该Orderer节点中的TLS目录下的ca.crt。设置该值，会将环境变量ORDERER_GENERAL_TLS_ROOTCAS的值覆盖")
}

func general_tls_RootCAs_LineEdit2_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("同路径1，根证书路径可以设置多个。")
}
func general_tls_RootCAs_LineEdit3_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("同路径1，根证书路径可以设置多个。")
}

func general_tls_ClientAuthEnabled_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_tls_ClientRootCAs_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_logLevel_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("环境变量ORDERER_GENERAL_LOGLEVEL的值覆盖")
}

func general_genesisMethod_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("环境变量ORDERER_GENERAL_GENESISMETHOD的值覆盖")
}

func general_genesisProfile_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}
func general_genesisFile_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer节点启动时所使用的创世纪块所在的路径，该块由[configtxgen -profile TwoOrgsOrdererGenesis -outputBlock ./channel-artifacts/genesis.block]命令生成。该值设置后，会将环境变量ORDERER_GENERAL_GENESISFILE的值覆盖。若在容器中部署，则该值为容器指向创世纪块的数据卷路径。")
}
func general_localMSPDir_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer节点使用的MSP的目录，设置该值，会将环境变量ORDERER_GENERAL_LOCALMSPDIR的值覆盖。该目录可用[cryptogen generate --config=./crypto-config.yaml]命令生成的Orderer组织中的MSP目录。若在容器中部署，则该目录值要使用容器与之相对应的数据卷路径。")
}

func general_localMSPID_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Orderer节点的MSP标识，设置该值，会将环境变量ORDERER_GENERAL_LOCALMSPID的值覆盖")
}

func general_profile_Enabled_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_profile_Address_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_bccsp_Default_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_bccsp_SW_Hash_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func general_bccsp_SW_Security_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}
func general_bccsp_SW_FileKeyStore_KeyStore_MPE(event *gui.QMouseEvent) {
    meconfig.head.EchoExplain("Ledger Type: The ledger type to provide to the orderer.")
}

func listChannelInfoButtonClick() {
    ordererCC.stackedConfigAndDisplay.SetCurrentIndex(0)
    meconfig.body.topic = mecommon.Topic_LIST_CHANNEL_INFO
}

func listChannelBasicInfoButtonClick() {
    ip := meconfig.head.nodeAddressLineEdit.Text()
    if ip == "" || strings.Index(ip,":") == -1 {
	meconfig.head.EchoExplain("节点ip非法，格式 _._._._:port")
	return
    }

    data := mecommon.GetSendEnvelope([]byte(""), mecommon.Topic_LIST_CHANNEL_BASIC_INFO)
    if data == nil {
	meconfig.head.EchoExplain("获取用于发送的配置数据失败")
	return
    }

    res, err := meclient.EverythingGiveMeIsJustOK(ip, data, 0)
    if err != nil {
	if res == nil {
	    meconfig.head.EchoExplain(err.Error() + " And " + "Response is nil")
	}else {
	    meconfig.head.EchoExplain(err.Error())
	}
    }else {
	//显示结果，对看服务器端getPeerBasicInfo()返回的结果信息的格式
	if res.Payload == nil {
	    meconfig.head.EchoExplain(res.Message)
	    return
	}
	buffer := bytes.NewBuffer(res.Payload)
	var results []string
	err = gob.NewDecoder(buffer).Decode(&results)
	if err != nil {
	    meconfig.head.EchoExplain("解析获取的节点channel信息出错")
	    return
	}

	row := len(results)
	containerNames := make([]string, row+1)
	containerNames[0] = "Peer节点"
	col := ordererCC.listAndDisplay.displayBasicInfoColumn
	ordererCC.listAndDisplay.displayBasicInfo.SetRowCount(row)
	for r := 0; r < row; r++ {
	    slices := strings.Split(results[r], csshare.SEPARATOR)
	    if len(slices) != col {
		meconfig.head.EchoExplain("解析获取的节点channel信息不符预期")
		//另一种处理方法是如下清理整个表格，然后当即退出
		//ordererCC.listAndDisplay.displayBasicInfo.SetRowCount(0)
		//ordererCC.listAndDisplay.displayBasicInfo.ClearContents()
		//return
	    }
	    containerNames[r+1] = slices[0]
	    for c := 0; c < col; c++ {
		//TODO:这里创建QTableWidgetItem可以更丰富，比如加入图标
		ordererCC.listAndDisplay.displayBasicInfo.SetItem(r, c, widgets.NewQTableWidgetItem2(slices[c], 0))
	    }
	}
	ordererCC.function.idComboBox.Clear()
	ordererCC.function.idComboBox.AddItems(containerNames)
	ordererCC.function.idComboBox.SetCurrentIndex(0)
	meconfig.head.EchoExplain("已获取通道信息，若要显示详细通道信息，请按格式填写 1.节点容器ID 2.连接的Orderer节点地址 3.所持Orderer端TLS CA证书路径(若开启TLS)，点击下方[详细信息]获取查看")
    }
}

func listChannelDetailInfoButtonClick() {
    ip := meconfig.head.nodeAddressLineEdit.Text()
    if ip == "" || strings.Index(ip, ":") == -1 {
	meconfig.head.EchoExplain("节点ip非法，格式 _._._._:port")
	return
    }

    containerID := ordererCC.function.idComboBox.CurrentText()
    ordererIP := ordererCC.function.ordererIPLineEdit.Text()
    caFilePath := ordererCC.function.caFilePathLineEdit.Text()
    var is_tls_enabled bool
    var ordererInfo, channelIDs string
    if containerID == "" || ordererCC.function.idComboBox.CurrentIndex() == 0 ||
       ordererIP == "" || strings.Index(ordererIP, ":") == -1 {
	   meconfig.head.EchoExplain(fmt.Sprintf("用于查询详细信息的容器ID或OrdererIP地址与要求不符[containerID:%s, idComboBoxCurrentIndex:%d, ordererIP:%s]", containerID, ordererCC.function.idComboBox.CurrentIndex(), ordererIP))
	return
    }
    //判断是否开启TLS，若开启是否填写caFilePath
    rowNum := ordererCC.listAndDisplay.displayBasicInfo.RowCount()
    if rowNum == 0 {
	meconfig.head.EchoExplain("未查询出节点信息")
	return
    }
    for i := 0; i < rowNum; i++ {
	//第0列是container名称
	if containerID == ordererCC.listAndDisplay.displayBasicInfo.Item(i, 0).Text() {
	    //第1列是containerID
	    containerID = ordererCC.listAndDisplay.displayBasicInfo.Item(i, 1).Text()
	    //第2列是是否开启TLS
	    if ordererCC.listAndDisplay.displayBasicInfo.Item(i, 2).Text() == "true" {
		if caFilePath == "" {
		    meconfig.head.EchoExplain("该节点开启了TLS，请输入节点所持的Orderer的TLS CA证书路径")
		    return
		}
		is_tls_enabled = true
	    }
	    //第3列是节点所加入的ChannelID
	    channelIDs = ordererCC.listAndDisplay.displayBasicInfo.Item(i, 3).Text()
	    //与服务端查询channel基本信息的函数getPeerChannelBasicInfo()中查询所加入channel字段时的后缀对看
	    //该字段若是正常的channelID，则会有(*^_^*)后缀，这里借用一下i定位一下这个(*^_^*)后缀
	    i = strings.Index(channelIDs, "(*^_^*)")
	    if i < 0 {
		meconfig.head.EchoExplain("该节点查询所加入的Channel信息失败或未加入Channel，无法查询Channel的详细信息")
		return
	    }
	    //截去(*^_^*)
	    channelIDs = channelIDs[:i]
	    break
	}
    }

    if is_tls_enabled {
	//格式:容器ID|_|OrdererIP:端口|_|channelIDs|_|CA路径
	ordererInfo = containerID + csshare.SEPARATOR + ordererIP + csshare.SEPARATOR + channelIDs + csshare.SEPARATOR + caFilePath
    }else {
	//容器ID1|_|OrdererIP:端口|_|channelIDs
	ordererInfo = containerID + csshare.SEPARATOR + ordererIP + csshare.SEPARATOR + channelIDs
    }

    data := mecommon.GetSendEnvelope([]byte(ordererInfo), mecommon.Topic_LIST_CHANNEL_DETAIL_INFO)
    if data == nil {
	meconfig.head.EchoExplain("获取用于发送的配置数据失败")
	return
    }

    res, err := meclient.EverythingGiveMeIsJustOK(ip, data, 0)
    if err != nil {
	if res == nil {
	    meconfig.head.EchoExplain(err.Error() + " And " + "Response is nil")
	}else {
	    meconfig.head.EchoExplain(err.Error())
	}
    }else {
	if res.Payload == nil {
	    meconfig.head.EchoExplain(res.Message)
	    return
	}
	buffer := bytes.NewBuffer(res.Payload)
	var results []*csshare.ChannelInfo
	//注册编进detailInfos中赋值给interfaces{}成员的结构体
	gob.Register(csshare.AnchorPeers{})
	gob.Register(csshare.MSPConfig{})
	gob.Register(csshare.Consortium{})
	gob.Register(csshare.OrdererAddresses{})

	err = gob.NewDecoder(buffer).Decode(&results)
	if err != nil {
	    errstr := fmt.Sprintf("解析获取的节点channel信息出错, err:%s", err)
	    meconfig.head.EchoExplain(errstr)
	    return
	}
	var detailInfosHTML string
	var tempStr string
	detailInfosHTML += "<html><body><table>"
	for _, di := range results {
	    detailInfosHTML += fmt.Sprintf("<tr><td><h4>%s</h4></td><td></td></tr>", di.ChannelID)
	    //如果简单的项都未获取，则默认其他的项也不可能获取，直接返回
	    if di.CreateTime == "" || di.Creator == "" {
		detailInfosHTML += fmt.Sprintf("<tr><td>%s</td><td></td></tr>", "获取失败")
		ordererCC.listAndDisplay.displayDetailInfo.SetHtml(detailInfosHTML)
		return
	    }

	    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;%s:</pre></td><td>%s</td></tr>", "创建时间", di.CreateTime)
	    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;%s:</pre></td><td>%s</td></tr>", "创建者", di.Creator)
	    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;%s:</pre></td><td>%s</td></tr>", "创建者所持MSP", di.CreatorMspID)
	    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;%s:</pre></td><td>%s</td></tr>", "创建者签名", di.CreatorSignatrue)
	    detailInfosHTML += fmt.Sprintf("<tr><td><pre><h4>&emsp;%s:</h4></pre></td><td></td></tr>", "频道组织")
	    for orgK, orgV := range di.OrgsInfo {
		detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;%s:</pre></td><td></td></tr>", orgK)
		for _, orgCV := range orgV {
		    //也可以用orgV range出来的key值进行判断
		    switch orgCV.(type) {
		    //这里因为上文gob.Register(csshare.AnchorPeers{})注册的均为结构体，所有这里不是指针
		    case csshare.AnchorPeers:
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td></td></tr>", "锚点")
			for _, ap := range orgCV.(csshare.AnchorPeers).AnchorPeers {
			    detailInfosHTML += fmt.Sprintf("<tr><td></td><td>%s:%d</td></tr>", ap.Host, ap.Port)
			}
		    case csshare.MSPConfig:
			mspC := orgCV.(csshare.MSPConfig)
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td></td></tr>", "MSP")
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "ID", mspC.Config.Name)
			for rtcIDX, rtcV := range mspC.Config.RootCerts {
			    decoded, err := base64.StdEncoding.DecodeString(rtcV)
			    if err != nil {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "根证书", rtcIDX+1, "解析失败")
			    }else {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "根证书", rtcIDX+1, decoded)
			    }
			}
			for adminIDX, adminV := range mspC.Config.Admins {
			    decoded, err := base64.StdEncoding.DecodeString(adminV)
			    if err != nil {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "管理员证书", adminIDX+1, "解析失败")
			    }else {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "管理员证书", adminIDX+1, decoded)
			    }
			}
			for trcIDX, trcV := range mspC.Config.TlsRootCerts {
			    decoded, err := base64.StdEncoding.DecodeString(trcV)
			    if err != nil {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "TLS根证书", trcIDX+1, "解析失败")
			    }else {
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s%d:</pre></td><td>%s</td></tr>",
				    "TLS根证书", trcIDX+1, decoded)
			    }
			}
		    default:
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s</td><td></td></tr>", "未知项")
		    }
		}
	    }//for orgK, orgV end

	    detailInfosHTML += fmt.Sprintf("<tr><td><pre><h4>&emsp;%s:</h4></pre></td><td></td></tr>", "通道策略")
	    for polK, polV := range di.Policies {
		detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;%s:</pre></td><td></td></tr>", polK)

		switch csshare.Policy_PolicyType(gjson.Get(polV, "type").Int()) {
		case csshare.Policy_UNKNOWN:
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "类型", "未知")
		case csshare.Policy_SIGNATURE:
		    /*
		    {
                              "type": 1,
                              "value": {
                                "identities": [
                                  {
                                    "principal": {
                                      "msp_identifier": "Org2MSP",
                                      "role": "MEMBER"
                                    },
                                    "principal_classification": "ROLE"
                                  }
                                ],
                                "rule": {
                                  "n_out_of": {
                                    "n": 1,
                                    "rules": [
                                      {
                                        "signed_by": 0
                                      }
                                    ]
                                  }
                                },
                                "version": 0
                              }
                            }
		    */
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "类型", "签名方式")
		    gjson.Get(polV, "value.identities").ForEach(func(key, value gjson.Result) bool {
			    switch gjson.Get(value.String(), "principal_classification").String() {
			    case "ROLE":
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s:</pre></td><td>%s中的%s</td></tr>",
				    "基于MSP角色验证", gjson.Get(value.String(), "principal.msp_identifier").String(),
				    gjson.Get(value.String(), "principal.role").String())
			    case "ORGANIZATION_UNIT":
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s:</pre></td><td>部门[%s]，部门证书标识[%s]</td></tr>",
				    "基于部门验证", gjson.Get(value.String(), "principal.organizational_unit_identifier").String(),
				    gjson.Get(value.String(), "principal.certifiers_identifier").String())
			    case "IDENTITY":
				detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>",
				    "基于身份验证", "（未实现详细信息呈现）")
			    default:
				return false
			    }
			    return true
		    })
		    tempStr = ""
		    gjson.Get(polV, "value.rule.rules").ForEach(func(key, value gjson.Result) bool {
			    tempStr += fmt.Sprintf(" [%s] ", gjson.Get(value.String(), "signed_by").String())
			    return true
		    })
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;&emsp;%s:</pre></td><td>共[%s]个用于验证的身份，由下标为%s的签名</td></tr>",
			"N_OUT_OF", gjson.Get(polV, "value.rule.n_out_of.n").String(), tempStr)
		case csshare.Policy_MSP:
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "类型", "MSP角色验证方式(未解析)")
		case csshare.Policy_IMPLICIT_META:
		    /*
		    {
                          "type": 3,
                          "value": {
                            "rule": "ANY",
                            "sub_policy": "Writers"
                          }
                        }
		    */
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "类型", "隐含元数据方式")
		    switch gjson.Get(polV, "value.rule").String() {
		    case "ANY":
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "规则", "任一子规则成立即可 [ANY]")
		    case "ALL":
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "规则", "所有子规则需全部满足 [ALL]")
		    case "MAJORITY":
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "规则", "需满足(子规则数)/2+1 [MAJORITY]")
		    default:
			detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "规则", "未知")
		    }
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "子策略", gjson.Get(polV, "value.sub_policy").String())

		default:
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;&emsp;%s:</pre></td><td>%d</td></tr>", "类型", "未知")

		}//switch gjson.Get(polV, "type").Int() end
	    }//for polK, polV := di.Policies end

	    detailInfosHTML += fmt.Sprintf("<tr><td><pre><h4>&emsp;%s:</h4></pre></td><td></td></tr>", "其他配置")
	    for _, cfV := range di.Config {
		switch cfV.(type) {
		case csshare.Consortium:
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "联盟组合(Consortium)", cfV.(csshare.Consortium).Name)
		case csshare.OrdererAddresses:
		    tempStr = ""
		    for _, oa := range cfV.(csshare.OrdererAddresses).Addresses {
			tempStr += fmt.Sprintf("%s<br/>", oa)
		    }
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;%s:</pre></td><td>%s</td></tr>", "Orderer服务地址", tempStr)
		default:
		    detailInfosHTML += fmt.Sprintf("<tr><td><pre>&emsp;&emsp;%s:</pre></td><td></td></tr>", "未知项")
		}
	    }//for cfk, cfv := range di.Config end
	}//for _, di := range results end
	detailInfosHTML += "</table></body></html>"

	ordererCC.listAndDisplay.displayDetailInfo.SetHtml(detailInfosHTML)

    }
}

//抽取idComboBox对应的listAndDisplay的channelID给addOrgGroup中的channelID组件赋值
func idComboBoxCurrentIndexChanged(index int) {
    if index >= 1 {
	channelIDs := ordererCC.listAndDisplay.displayBasicInfo.Item(index, 3).Text()
	//正常的channelID
	i := strings.Index(channelIDs, "(*^_^*)")
	if i > 0 {
	    ordererCC.addOrg.channelID.Clear()
	    channelIDs = channelIDs[:i]
	    ordererCC.addOrg.channelID.AddItems(strings.Split(channelIDs, ","))
	}
    }
}

func addNewOrgButtonClick() {
    meconfig.body.topic = mecommon.Topic_ADD_ORG
    //抽取idComboBox对应的listAndDisplay的channelID给addOrgGroup中的channelID组件赋值
    row := ordererCC.function.idComboBox.CurrentIndex()
    if row >=1 {
	channelIDs := ordererCC.listAndDisplay.displayBasicInfo.Item(row, 3).Text()
	//正常的channelID
	i := strings.Index(channelIDs, "(*^_^*)")
	if i > 0 {
	    ordererCC.addOrg.channelID.Clear()
	    channelIDs = channelIDs[:i]
	    ordererCC.addOrg.channelID.AddItems(strings.Split(channelIDs, ","))
	}
    }

    ordererCC.stackedConfigAndDisplay.SetCurrentIndex(1)
}

func addOneSignNodeButtonClick(ao *addOrgGroup) {
    ao.signNodeNum += 1
    signNodeIP := widgets.NewQLineEdit(nil)
    signNodeIP.SetObjectName(fmt.Sprintf("SignNodeIP%d", ao.signNodeNum))
    signNodeContainerID := widgets.NewQLineEdit(nil)
    signNodeContainerID.SetObjectName(fmt.Sprintf("SignNodeContainerID%d", ao.signNodeNum))
    signNodeFCP := widgets.NewQLineEdit(nil)
    signNodeFCP.SetObjectName(fmt.Sprintf("SignNodeMspPath%d", ao.signNodeNum))
    signNodeFirstLayout := widgets.NewQHBoxLayout()
    signNodeFirstLayout.AddWidget(signNodeIP, 1, 0)
    signNodeFirstLayout.AddWidget(signNodeContainerID, 1, 0)
    signNodeFirstLayout.AddWidget(signNodeFCP, 2, 0)
    ao.signNodeLayout.AddLayout(signNodeFirstLayout, 0)
}

func addOneAnchorPeerButtonClick(ao *addOrgGroup) {
    orgAnchorPeer := widgets.NewQLineEdit(nil)
    ao.orgAnchorPeerNum += 1
    orgAnchorPeer.SetPlaceholderText(fmt.Sprintf("锚点%d", ao.orgAnchorPeerNum))
    orgAnchorPeer.SetObjectName(fmt.Sprintf("AnchorPeer%d", ao.orgAnchorPeerNum))
    ao.orgAnchorPeersLayout.AddWidget(orgAnchorPeer, 0, 0)
}

func addOneSpecButtonClick(ao *addOrgGroup) {
    ao.orgSpecNum += 1
    orgSpecHostname := widgets.NewQLineEdit(nil)
    orgSpecHostname.SetObjectName(fmt.Sprintf("SpecHostName%d", ao.orgSpecNum))
    orgSpecCommonName := widgets.NewQLineEdit(nil)
    orgSpecCommonName.SetObjectName(fmt.Sprintf("SpecCommonName%d", ao.orgSpecNum))
    orgSpecSANS := widgets.NewQLineEdit(nil)
    orgSpecSANS.SetObjectName(fmt.Sprintf("SpecSANS%d", ao.orgSpecNum))
    orgChildLayout := widgets.NewQFormLayout(nil)
    orgChildLayout.AddRow3("主机名", orgSpecHostname)
    orgChildLayout.AddRow3("CN", orgSpecCommonName)
    orgChildLayout.AddRow3("SANS", orgSpecSANS)
    orgChildLayout.AddRow3("-----------", nil)
    ao.orgSpecsLayout.AddLayout(orgChildLayout, 0)
}

func modifyCurrentOrgButtonClick() {

}

func deleteCurrentOrgButtonClick() {

}
