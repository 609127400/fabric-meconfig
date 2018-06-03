

package main

import (
    "fmt"
    "net"
    "bytes"
    "log"
    "strings"
    "os"
    "os/signal"
    "syscall"
    "time"
    "encoding/gob"
    "google.golang.org/grpc"
    "google.golang.org/grpc/peer"
    "github.com/spf13/viper"
    //"github.com/golang/protobuf/proto"
    "golang.org/x/net/context"
    flocalconfig "github.com/hyperledger/fabric/orderer/localconfig"
    fprotoscommon "github.com/hyperledger/fabric/protos/common"
    fprotospeer "github.com/hyperledger/fabric/protos/peer"
    "github.com/fabric-meconfig/common/protos"
    "github.com/fabric-meconfig/common/csshare"
)

const port int = 10000
const pathForTempData string = "/var/meserver"
const pathForTempTool string = "./tools"
const pathForTempSave string = pathForTempData + "/save"
const dirForTempSave  string = "save"

const tool_CONFIGTXGEN string = pathForTempTool + "/configtxgen"
const tool_CONFIGTXLATOR string = pathForTempTool + "/configtxlator"
const ip_CONFIGTXLATOR string = "127.0.0.1:7059"
const tool_CRYPTOGEN string = pathForTempTool + "/cryptogen"
const tool_JQ string = pathForTempTool + "/jq"

//节点的FABRIC_CFG_PATH环境变量key
const peer_FABRIC_CFG_PATH = "FABRIC_CFG_PATH"
//peer core.yaml中的mspConfigPath项的值
const peer_mspConfigPath = "msp"
//$FABRIC_CFG_PATH/peer_mspConfigPath组成了节点的本地msp地址
//core是peer/main.go中cmdRoot定义的
const peer_ConfigFile = "core.yaml"

var (
    nodeEnv *viper.Viper
    logger *log.Logger
)

func init() {
    //载入配置
    nodeEnv = viper.New()
    nodeEnv.AddConfigPath("./")
    nodeEnv.SetConfigName("config")
    nodeEnv.SetConfigType("yaml")
    nodeEnv.WatchConfig()

    err := nodeEnv.ReadInConfig()
    if err != nil {
	panic(fmt.Errorf("Fatal error read config file: %s \n", err))
    }
    //创建一个临时存放文件的目录 - 顺便建save目录
    err = os.MkdirAll(pathForTempSave, 0755)
    if err != nil {
        panic(fmt.Errorf("Fatal error create dir for temp data: %s \n", err))
    }
    //创建日志文件和日志对象
    server_log, err := os.Create("server.log")
    if err != nil {
        log.Fatalln("create server log file error")
    }
    logger = log.New(server_log,"[Info]", log.Llongfile)
    logger.SetPrefix("[MEServer-Debug]")
    logger.SetFlags(log.Lshortfile)

    STEPS_EXPLAIN = make(map[DEALSTATE]string)
    STEPS_EXPLAIN[DoNothing] = "未初始化"
    STEPS_EXPLAIN[GettedCurrentContainerInfo] = "获取当前节点容器信息"
    STEPS_EXPLAIN[WrittedConfigDataToFile] = "将新配置数据写入配置文件"
    STEPS_EXPLAIN[UpdatedContainerInfo] = "根据新配置数据更新容器信息"
    STEPS_EXPLAIN[WrittedDockerComposeFile] = "容器信息写入docker-compose文件"
    STEPS_EXPLAIN[CopiedConfigFileToCurrentContainer] = "将配置文件复制到现有容器中"
    STEPS_EXPLAIN[CommittedCurrentContainer] = "通过docker commit提交现有容器生成新容器镜像"
    STEPS_EXPLAIN[DeleteCurrentContainer] = "删除现有容器"
    STEPS_EXPLAIN[RanNewContainer] = "根据新的容器镜像启动新容器"
    STEPS_EXPLAIN[CleanedTempData] = "清理临时文件"
    STEPS_EXPLAIN[AllDone] = "所有升级步骤均已成功完成"

}

type meserver struct {
    /*1.当是容器部署时，若当次配置所有容器全部更新成功，则置为""，
    若存在不成功的容器，则记录当次更新的时间点，下次更新时以此值
    进行过滤更新过的容器
    2.当是本机部署时，
    */
    lastStartContainerTime string
    //当是容器部署时，记录每个当次处理的 容器ID（前12位）- 基础信息（格式不定）
    //TODO:该map暂不清空，可以在处理逻辑中加入清空的条件进行清空
    containerBasicInfo map[string]string
    //假定一台物理机上的节点部署方式是统一的，即要么都是本机部署，要么都是容器部署
    //标识节点是在容器部署还是在本机部署 - 三种状态：未检查，本机部署，容器部署
    deployStatus mecommon.DeployStatus
}

//接收客户端的消息
func (ms *meserver) DealConfigurationData(ctx context.Context, env *fprotoscommon.Envelope) (*fprotospeer.Response, error) {
    //获取客户端IP
    p, ok := peer.FromContext(ctx)
    if !ok || p.Addr == net.Addr(nil) {
        fmt.Printf("receive unknown client's configuration data\n")
	err := fmt.Errorf("client's ip is unknown")
	return &fprotospeer.Response{ Status: int32(int32(fprotoscommon.Status_BAD_REQUEST)), Message: err.Error() }, err
    }

    addrSlice := strings.Split(p.Addr.String(), ":")
    fmt.Printf("receive %s 's configuration data, start to deal...\n",addrSlice[0])

    topic, data, err := mecommon.GetTopicAndPayloadDataFromEnvelope(env)
    if err != nil {
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST) }, err
    }

    switch (topic & mecommon.Topic_MASK){
    case mecommon.Topic_PEER_CONFIG:
	logger.Printf("receive %s 's configuration data[PEER_CONFIG], start to deal...\n",addrSlice[0])
	err = dealPeerConfig(data)
	if err != nil {
	    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR), Message:err.Error() }, err
	}
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS) }, nil
    case mecommon.Topic_ORDERER_CONFIG:
	logger.Printf("receive %s 's configuration data[ORDERER_CONFIG], start to deal...\n",addrSlice[0])
	return ms.dealOrdererConfig(data)
    case mecommon.Topic_ORDERER_CHANNEL_CONFIG:
	logger.Printf("receive %s 's configuration data[ORDERER_CHANNEL_CONFIG], start to deal...\n",addrSlice[0])
	return ms.dealOrdererChannelConfig(topic, data)
    default:
	err = fmt.Errorf("不能识别配置主题")
	logger.Println("不能识别配置主题")
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST), Message:err.Error() }, err
    }
}

func dealPeerConfig(data []byte) error {
    return nil
}

func dealPeerCommand(cmd []byte) error {
    return nil
}

/*---------------------------------------------------

----------------------------------------------------*/
func (ms *meserver) dealOrdererConfig(data []byte) (*fprotospeer.Response, error) {
    if ms.deployStatus == mecommon.DeployStatus_UNCHECKED {
	is_on_container := isDeployInContainer("orderer", "", "grep", "chaincode")
	if is_on_container {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_DC
	}else {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_PM
	}
    }

    configName := "orderer.yaml"

    if ms.deployStatus == mecommon.DeployStatus_IS_ON_DC {
	//step1获取本机容器ID，容器使用的镜像ID
	containersInfo := getContainersInfo(ms.lastStartContainerTime, flocalconfig.Prefix, "orderer", "", "grep")
	if len(containersInfo) == 0 {
	    logger.Println("dealOrdererConfig：未获取容器信息")
	    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, fmt.Errorf("dealOrdererConfig：未获取容器信息")
	}
	//设置配置点
	ms.lastStartContainerTime = time.Now().Format("20060102150405")
	//step2
	v := writeNewConfigDataToPathForTempData(data, configName, containersInfo)
	if v == nil {
	    logger.Printf("meserver运行目录生成新配置文件%s失败\n", configName)
	    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, fmt.Errorf("meserver运行目录生成新配置文件%s失败", configName)
	}
	//step3
	copyConfigFileToConfigPath(configName, containersInfo)
	//step4
	dockerCommitAndStopAndDelteCurrentContainer(containersInfo)
	//step5
	updateContainerInfo(flocalconfig.Prefix, v, containersInfo)
	//step6
	writeTempDockerComposeFileByCurrentContainerInfo(containersInfo)
	//step7 - 测试时注销此步
	dockerComposeUpNewContainer(containersInfo)

	results, alldone := reportUpdateResults(containersInfo)
	if !alldone {
	    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR), Message:results }, fmt.Errorf("未全部更新成功")
	}
	//全部更新成功，则清空配置点
	ms.lastStartContainerTime = ""
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:results }, nil
    }

    //部署在本机
    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"本机部署，暂未执行" }, nil
}

func (ms *meserver) dealOrdererChannelConfig(topic mecommon.Topic, data []byte) (*fprotospeer.Response, error) {
    switch (topic){
    case mecommon.Topic_LIST_CHANNEL_BASIC_INFO:
	return ms.dealListBasicChannelInfo()
    case mecommon.Topic_LIST_CHANNEL_DETAIL_INFO:
	return ms.dealListDetailChannelInfo(data)
    case mecommon.Topic_ADD_ORG:
	return ms.dealAddOrg(data)
    case mecommon.Topic_MODIFY_ORG:
    case mecommon.Topic_DELETE_ORG:
    default:
	return &fprotospeer.Response{ Status: int32(int32(fprotoscommon.Status_BAD_REQUEST)), Message:"未识别的配置主题" }, nil
    }
    return &fprotospeer.Response{ Status: int32(int32(fprotoscommon.Status_BAD_REQUEST)), Message:"未识别的配置主题" }, nil
}

func (ms *meserver) dealListBasicChannelInfo() (*fprotospeer.Response, error) {
    if ms.deployStatus == mecommon.DeployStatus_UNCHECKED {
	is_on_container := isDeployInContainer("peer node start", "", "grep", "chaincode")
	if is_on_container {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_DC
	}else {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_PM
	}
    }

    if ms.deployStatus == mecommon.DeployStatus_IS_ON_DC {
	basicInfos := getPeerChannelBasicInfo()
	//记录一下基础信息，供客户端获取详细信息时，服务端再使用
	for _, one := range basicInfos {
	    pos := strings.Index(one, csshare.SEPARATOR)
	    ms.containerBasicInfo[one[:pos]] = one
	}
	buffer := &bytes.Buffer{}
	err := gob.NewEncoder(buffer).Encode(basicInfos)
	if err != nil {
	    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, err
	}
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"获取channelID成功", Payload:buffer.Bytes() }, nil
    }
    //本机部署
    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"本机部署，暂未执行" }, nil
}

func (ms *meserver) dealListDetailChannelInfo(data []byte) (*fprotospeer.Response, error) {
    if ms.deployStatus == mecommon.DeployStatus_UNCHECKED {
	is_on_container := isDeployInContainer("peer node start", "", "grep", "chaincode")
	if is_on_container {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_DC
	}else {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_PM
	}
    }

    if data == nil || len(strings.Split(string(data), csshare.SEPARATOR)) < 3 {
	return &fprotospeer.Response{ Status: int32(int32(fprotoscommon.Status_BAD_REQUEST)), Message:"发送用于查询详细信息的Orderer信息不符预期" }, nil
    }

    if ms.deployStatus == mecommon.DeployStatus_IS_ON_DC {
	detailInfos := getPeerChannelDetailInfo(string(data))
	if detailInfos == nil {
	    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, fmt.Errorf("未获取频道信息，请检查服务端日志[server.log]")
	}
	buffer := &bytes.Buffer{}
	//注册编进detailInfos中赋值给interfaces{}成员的结构体
	gob.Register(csshare.AnchorPeers{})
	gob.Register(csshare.MSPConfig{})
	gob.Register(csshare.Consortium{})
	gob.Register(csshare.OrdererAddresses{})

	err := gob.NewEncoder(buffer).Encode(detailInfos)
	if err != nil {
	    logger.Printf("gob Encode detailInfos error, err: %s\n", err)
	    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, err
	}
	return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"获取channel详细信息成功", Payload:buffer.Bytes() }, nil
    }
    //本机部署
    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"本机部署，暂未执行" }, nil
}

//data由func (ao *addOrgGroup) getConfigurationData()生成
func (ms *meserver)dealAddOrg(data []byte) (*fprotospeer.Response, error) {
    if ms.deployStatus == mecommon.DeployStatus_UNCHECKED {
	is_on_container := isDeployInContainer("peer node start", "", "grep", "chaincode")
	if is_on_container {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_DC
	}else {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_PM
	}
    }

    if data == nil {
	return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_BAD_REQUEST) }, fmt.Errorf("发送数据为空")
    }

    if ms.deployStatus == mecommon.DeployStatus_IS_ON_DC {
	err := addOrgDataToChannelConfig(data)
	clearJob(pathForTempData, []string{dirForTempSave})
	if err != nil {
	    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR), Message:"添加新组织配置失败" }, err
	}
	return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"添加新组织配置数据成功" }, nil
    }

    //本机部署
    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"本机部署，暂未执行" }, nil
}

func dealModifyOrg() (*fprotospeer.Response, error) {
    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"暂未实现" }, nil
}

func dealDeleteOrg() (*fprotospeer.Response, error) {
    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"暂未实现" }, nil
}

/*---------------------------------------------------

----------------------------------------------------*/
func dealOrdererCommand(cmd []byte) error {
    return nil
}

func (ms *meserver) DealCommandData(con context.Context, env *fprotoscommon.Envelope) (*fprotospeer.Response, error) {
    /*
    case pcommon.Topic_PEER_COMMAND:
	logger.Printf("receive %s 's configuration data[PEER_COMMAND], start to deal...\n",addrSlice[0])
	dealPeerCommand(data)
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"暂不处理" }, nil
    */
    /*
    case pcommon.Topic_ORDERER_COMMAND:
	dealOrdererCommand(data)
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"暂不处理" }, nil
    */
    return nil,nil
}

func dealOrdererCommandData(data []byte) error {
    return nil
}

func dealPeerCommandData(data []byte) error {
    return nil
}

func (ms *meserver) IamYou(ctx context.Context, env *fprotoscommon.Envelope) (*fprotospeer.Response, error) {
    //获取客户端IP
    p, ok := peer.FromContext(ctx)
    if !ok || p.Addr == net.Addr(nil) {
        fmt.Printf("receive unknown client's configuration data\n")
        logger.Printf("receive unknown client's configuration data\n")
	err := fmt.Errorf("client's ip is unknown")
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST), Message: err.Error() }, err
    }

    addrSlice := strings.Split(p.Addr.String(), ":")
    topic, data, err := mecommon.GetTopicAndPayloadDataFromEnvelope(env)
    if err != nil {
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST) }, err
    }
    fmt.Printf("receive %s 's [%s] data, start to deal...\n",addrSlice[0], topic)
    logger.Printf("receive %s 's [%s] data, start to deal...\n",addrSlice[0], topic)

    switch (topic & mecommon.Topic_MASK){
    case mecommon.Topic_I_AM_YOU:
	return ms.dealIamYou(topic, data)
    default:
	err = fmt.Errorf("不能识别配置主题")
	logger.Println("不能识别配置主题")
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST), Message:err.Error() }, err
    }
}

func (ms *meserver) dealIamYou(topic mecommon.Topic, data []byte)(*fprotospeer.Response, error) {
    switch topic {
    case mecommon.Topic_SIGN_MY_UPDATE_CONFIG:
	return ms.dealSignUpdateConfig(data)
    default:
	return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_BAD_REQUEST), Message:"未识别的配置主题" }, nil
    }
    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_BAD_REQUEST), Message:"未识别的配置主题" }, nil
}

func (ms *meserver) dealSignUpdateConfig(data []byte) (*fprotospeer.Response, error) {
    if ms.deployStatus == mecommon.DeployStatus_UNCHECKED {
	is_on_container := isDeployInContainer("peer node start", "", "grep", "chaincode")
	if is_on_container {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_DC
	}else {
	    ms.deployStatus = mecommon.DeployStatus_IS_ON_PM
	}
    }

    if ms.deployStatus == mecommon.DeployStatus_IS_ON_DC {
	signedData := signUpdateConfig(data)
	if signedData == nil {
	    return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_INTERNAL_SERVER_ERROR) }, fmt.Errorf("签名失败")
	}
	return &fprotospeer.Response{ Status:int32(fprotoscommon.Status_SUCCESS), Message:"签名成功", Payload:signedData }, nil
    }

    return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_SUCCESS), Message:"本机部署，暂未执行" }, nil
}

func main(){
    lis,err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
    //TODO:完善服务端日志记录
    if err != nil {
	fmt.Printf("failed to listen 10000\n")
    }else{
	fmt.Printf("success to listen to 10000\n")
    }
    //TODO:与客户端配合，完善安全连接选项
    var opts []grpc.ServerOption
    grpcServer := grpc.NewServer(opts...)
    ms := &meserver{
	deployStatus: mecommon.DeployStatus_UNCHECKED,
	containerBasicInfo: make(map[string]string),
    }
    mecommon.RegisterMEDealerServer(grpcServer,ms)

    //捕获系统signal，释放监控的端口
    ssc := make(chan os.Signal, 1)
    signal.Notify(ssc, os.Interrupt)
    signal.Notify(ssc, syscall.SIGTERM)

    gsc := make(chan error, 1)

    go func(){
	err := grpcServer.Serve(lis)
	gsc <-err
    }()

    select {
    case <-ssc:
	fmt.Println("")
	fmt.Println("强制退出GRPC服务端")
	grpcServer.Stop()
	signal.Stop(ssc)
	fmt.Println("清理完毕GRPC服务端")
    case err = <-gsc:
	fmt.Println("")
	fmt.Println("GRPC服务端出现致命错误")
	fmt.Println(err)
    }
}
