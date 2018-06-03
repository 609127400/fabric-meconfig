
package gui

import (
    "fmt"
    "net"
    "time"
    "strings"
    "github.com/tatsushid/go-fastping"
    "github.com/fabric-meconfig/common/meclient"
    "github.com/fabric-meconfig/common/protos"
)






const MAX_PING_TTL = 128 //MilliSecond
const MAX_PING_TIME = 10 //次
const MAX_PING_TIME_OUT = 3 //秒


//testConnectButton Click触发函数
func testConnectButtonClick() {
    meconfig.head.testResultLabel.SetText("")
    if meconfig.is_constructed != true {
	return
    }
    //TODO:更严格的检查，判定输入的是否是合法的IP
    var addr string = meconfig.head.nodeAddressLineEdit.Text()
    addrSlice := strings.Split(addr, ":")
    if len(addrSlice) != 2 {
	meconfig.head.EchoExplain("节点ip非法，格式 _._._._:port")
	return
    }
    ip := addrSlice[0]
    pinger := fastping.NewPinger()
    //TODO:做支持ipv6的选项
    netProto := "ip4:icmp"
    ra, err := net.ResolveIPAddr(netProto, ip)
    if err != nil {
	meconfig.head.testResultLabel.SetText("程序转换地址错误")
	return
    }
    type response struct {
	addr *net.IPAddr
	rtt  time.Duration
    }

    var result *response = nil
    recv_count := 0
    //组装pinger
    pinger.AddIPAddr(ra)
    onRecv, onIdle := make(chan *response),make(chan bool)
    pinger.OnRecv = func (addr *net.IPAddr, t time.Duration) {
	onRecv <- &response{ addr:addr, rtt:t }
    }
    pinger.OnIdle = func () {
	onIdle <- true
    }
    //运行，timeout为微秒
    pinger.MaxRTT = time.Millisecond * MAX_PING_TTL
    pinger.RunLoop()
    ticker := time.NewTicker(time.Second * MAX_PING_TIME_OUT)
    time_out := false
    recv_string := ""
    for {
	select {
	case <-ticker.C:
	    if recv_count > int((MAX_PING_TIME_OUT*time.Second)/pinger.MaxRTT*4/5) { //次数在80%以上，算是网络畅通
		meconfig.head.testResultLabel.SetText("与节点网络畅通")
	    }else if recv_count > 0 {
		meconfig.head.testResultLabel.SetText("网络较慢或存在丢包可能")
	    }else {
		meconfig.head.testResultLabel.SetText("无法连接到节点")
	    }
	    time_out = true
	case <-pinger.Done():
	    if err = pinger.Err(); err != nil {
		meconfig.head.testResultLabel.SetText(fmt.Sprintf("Ping failed:%s", err))
	    }
	case res := <-onRecv:
	    result = res
	    recv_count++
	    case <-onIdle: //TTL，每128毫秒检查是否收到回复
	    if result == nil {
		meconfig.head.testResultLabel.SetText("目标节点无响应...")
	    }else {
		recv_string += fmt.Sprintf("来自%s的回复: 时间:%d,TTL:%d\n",result.addr.String(),result.rtt,MAX_PING_TTL)
		meconfig.head.testResultLabel.SetText(recv_string)
		result = nil
	    }
	}
	if time_out { break }
    }
    ticker.Stop()
    pinger.Stop()
}

//body部分的orderer面板与peer面板之间切换
func topicComboBoxCurrentIndexChanged(index int) {
    //这里的switch case与head.topicComboBox所填写的值前后对应
    //topicComboBox.AddItems([]string{"PEER_CONFIG","PEER_COMMAND","ORDERER_CONFIG","ORDERER_CHANNEL_CONFIG","ORDERER_COMMAND"})
    //TODO:连接变化的body的显示主体
    switch(index) {
    case 0:
	meconfig.body.topic = mecommon.Topic_PEER_CONFIG
	meconfig.head.EchoExplain("配置Peer节点")
    case 1:
	meconfig.body.topic = mecommon.Topic_PEER_COMMAND
	meconfig.head.EchoExplain("向Peer节点发送执行命令")
    case 2:
	meconfig.body.topic = mecommon.Topic_ORDERER_CONFIG
	meconfig.head.EchoExplain("配置Orderer节点")
    case 3:
	meconfig.body.topic = mecommon.Topic_ORDERER_CHANNEL_CONFIG
	meconfig.head.EchoExplain("配置Orderer节点通道")
    case 4:
	meconfig.body.topic = mecommon.Topic_ORDERER_COMMAND
	meconfig.head.EchoExplain("向Orderer节点发送执行命令")
    }

    meconfig.body.stackedtopics.SetCurrentIndex(index)
}

func resetButtonClicked() {

}

func applyButtonClicked() {
    //topicComboBox.AddItems([]string{"PEER_CONFIG","PEER_COMMAND","ORDERER_CONFIG","ORDERER_CHANNEL_CONFIG","ORDERER_COMMAND"})
    if mecommon.TopicIsConfig(meconfig.head.topicComboBox.CurrentIndex()) {
	ip := meconfig.head.nodeAddressLineEdit.Text()
	if ip == "" || strings.Index(ip,":") == -1 {
	    meconfig.head.EchoExplain("节点ip非法，格式 _._._._:port")
	    return
	}

	config := meconfig.GetConfigurationData()
	if config == nil {
	    meconfig.head.EchoExplain("获取配置数据失败，请检查配置填写是否符合要求")
	    return
	}

	data := mecommon.GetSendEnvelope(config, meconfig.body.topic)

	if data == nil {
	    meconfig.head.EchoExplain("获取用于发送的配置数据失败")
	    return
	}

	res, err := meclient.EverythingGiveMeIsJustOK(ip, data, 0)
	if err != nil {
	    if res == nil {
		meconfig.head.EchoExplain(err.Error() + " And " + "Response is nil")
	    }else{
		meconfig.head.EchoExplain(err.Error() + " And\n" + res.Message)
	    }
	}else{
	    meconfig.head.EchoExplain("应用成功 And\n" + res.Message)
	}
    }else {
	meconfig.head.EchoExplain("命令窗口，暂未动作")
    }
}

/*
//TODO:关闭的时候，清理工作
func close() {
    meclient.CloseAllConnection ()
}
*/
