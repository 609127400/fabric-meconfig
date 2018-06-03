
package main


import (
    "bytes"
    "fmt"
    "io/ioutil"
    "encoding/base64"
    "encoding/json"
    "encoding/gob"
    "os"
    "os/exec"
    "strings"
    "time"
    "strconv"
    "github.com/spf13/viper"
    "github.com/golang/protobuf/proto"
    fcoreconfig "github.com/hyperledger/fabric/core/config"
    fpeercommon "github.com/hyperledger/fabric/peer/common"
    flocalsigner "github.com/hyperledger/fabric/common/localmsp"
    fprotoscommon "github.com/hyperledger/fabric/protos/common"
    fprotosutils "github.com/hyperledger/fabric/protos/utils"
    fcommonconfigtx "github.com/hyperledger/fabric/common/configtx"
    fcommonutil "github.com/hyperledger/fabric/common/util"
    "github.com/fabric-meconfig/common/metadata"
    "github.com/fabric-meconfig/common/csshare"
    "github.com/fabric-meconfig/common/meclient"
    "github.com/fabric-meconfig/common/protos"
)

//                                             stdout  stderr  err
func doCommand(shell, flag, strcmd string) (string, string, error) {
    cmd := exec.Command(shell, flag, strcmd)
    stderr, err := cmd.StderrPipe()
    if err != nil {
	return "", "", fmt.Errorf("Fatal error: %s", err)
    }
    stdout, err := cmd.StdoutPipe()
    if err != nil {
	return "", "", fmt.Errorf("Fatal error: %s", err)
    }

    if err = cmd.Start(); err != nil {
	return "", "", fmt.Errorf("Fatal error: %s", err)
    }

    stdout_content, _ := ioutil.ReadAll(stdout)
    stderr_content, _ := ioutil.ReadAll(stderr)

    if err = cmd.Wait(); err != nil {
	//命令运行出错
	return string(stdout_content), string(stderr_content), fmt.Errorf("Fatal error: %s", err)
    }

    return string(stdout_content), string(stderr_content), nil
}

//通过关键字查看节点是否部署在容器中，关键字如orderer，peer，kafka
func isDeployInContainer(include_key1 string, include_key2 string, exclude_keys ...string) bool {
    var include_string string
    if include_key2 == "" {
	include_string = fmt.Sprintf("| grep -E \"%s\" ",include_key1)
    }else{
	include_string = fmt.Sprintf("| grep -E \"%s|%s\" ",include_key1,include_key2)
    }

    var exclude_string string
    for _, one := range exclude_keys {
	exclude_string += fmt.Sprintf("| grep -v \"%s\" ", one)
    }

    var strcmd string
    //--fromat='xxxx'是关键字的覆盖范围，搜索的时候要在这些范围内搜索
    strcmd = fmt.Sprintf("docker ps --format='{{.ID}} {{.Names}} {{.Command}}' %s %s", include_string, exclude_string)
    stdout, stderr, err := doCommand("bash","-c", strcmd)
    //如果命令执行出错(压根就没安装docker)，或未查找到指定的，则表明不存在指定容器，则断定是本机部署，
    //否则，断定是容器部署
    if err != nil { logger.Println("doCommand err, stderr: %s", stderr) }
    return (err == nil && stdout != "")
}

//目前设计支持2个include_key，任意个exclude_key
//exclude_key只要用于在搜索容器信息时，需要排除的行所包含的关键字，如grep,chaincode等
//grep进行的筛选基础是docker ps --format='...'中所列的字段
func getContainerIDs (include_key1, include_key2 string, exclude_keys... string) []string {
    var include_string string
    if include_key2 == "" {
	include_string = fmt.Sprintf("| grep -E \"%s\" ",include_key1)
    }else{
	include_string = fmt.Sprintf("| grep -E \"%s|%s\" ",include_key1,include_key2)
    }

    var exclude_string string
    for _, one := range exclude_keys {
	exclude_string += fmt.Sprintf("| grep -v %s ", one)
    }

    var strcmd string
    //样例：docker ps --format='{{.ID}} {{.Names}} {{.Command}}' | grep peer | grep -v grep | grep -v chaincode
    //这里format罗列的字段，是后边grep进行筛选的基础
    strcmd = fmt.Sprintf("docker ps --format='{{.ID}} {{.Names}} {{.Command}}' %s %s", include_string, exclude_string)

    stdout, stderr, err := doCommand("bash","-c", strcmd)
    if err != nil || stdout == "" {
	logger.Println("doCommand err, stderr: ", stderr)
	return nil
    }
    containers_info := strings.Split(stdout, "\n")
    containers_num := len(containers_info) - 1 //用\n分割信息，最后一个是空
    containerIDs := make([]string, containers_num)
    for i := 0; i < containers_num; i++ {
	//从每个containers_info中截取容器ID（从0开始到遇到的第一个空格的位置）
	//这里以空格标识，取决于strcmd中--format=的显示模式是以空格隔断的
	blank_pos := strings.Index(containers_info[i], " ")
	if blank_pos == -1 { continue }
	containerIDs[i] = containers_info[i][:blank_pos]
    }

    return containerIDs
}

//TODO:在对容器做操作之前，对当前容器进行备份
func backupContainer(containerID string) error {
    return nil
}

func isDirAndExists(path string) bool {
    fileInfo, err := os.Stat(path)
    if err != nil {
        return os.IsExist(err)
    } else {
        return fileInfo.IsDir()
    }
}

//从container信息中获取主机与容器对应的一对有效的数据卷路径，
//source_path用于viper写入新的orderer.yaml
//destination_path用于重启容器时，作为容器内部的复制源，复制到orderer程序能够识别的配置路径（这样orderer重新运行时就可以读取了）
func getOneValidSourceAndDestinationPathFromContainer(containerID string) (string, string) {
    var strcmd, source_path, destination_path string
    //docker inspect --format='{{with index .Mounts 1}}{{.Type}}{{end}}' 65fc 以根上下文（.所代表）中的Mounts下第1个元素为上下文，查看上下文中的Type元素
    //docker inspect --format='{{index .HostConfig.Binds 1}}' 65fc 查看根上下文中HostConfig中第1项元素的Binds元素
    //尝试循环5个容器挂载的数据卷，若依然没有是一个目录数据卷，则返回失败
    var counter int
    for counter = 0; counter < 5; counter++ {
	strcmd = fmt.Sprintf("docker inspect --format='{{index .HostConfig.Binds %d}}' %s", counter, containerID)
	stdout, stderr, err := doCommand("bash","-c", strcmd)
	if err != nil || stdout == "" {
	    //do nothing，继续尝试下一个Blinds
	    logger.Println("doCommand err, stderr: ", stderr)
	}else {
	    //stdout样例：/home/wyz/fabric/fabric-samples/first-network/channel-artifacts/genesis.block:/var/hyperledger/orderer/orderer.genesis.block:rw
	    //查看是否且是否是目录
	    source_path = strings.Split(stdout, ":")[0]
	    destination_path = strings.Split(stdout, ":")[1]
	    if !isDirAndExists(source_path) { continue }
	    break
	}
    }
    if counter == 5 { return "", "" }

    return source_path, destination_path
}

//返回的路径均不带最后的/，正常情况下一定会存在一个有效配置路径返回
func getOneValidOrdererConfigPath(containerID string) string {
    var configPath string
    //路径1，FABRIC_CFG_PATH
    strcmd := fmt.Sprintf("docker exec %s env | grep FABRIC_CFG_PATH", containerID)
    stdout, stderr, err := doCommand("bash", "-c", strcmd)
    if err != nil || stdout == "" {
	logger.Println("doCommand err, stderr: ", stderr)
    }else {
	envPair := strings.Split(stdout, "=")
	if len(envPair) == 2 {
	    configPath = strings.Trim(envPair[1], " \n")
	    if configPath != "" { return configPath }
	}
    }
    //路径2，orderer程序所在路径
    strcmd = fmt.Sprintf("docker exec %s which orderer", containerID)
    stdout, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil || stdout == "" {
	logger.Println("doCommand err, stderr: ", stderr)
    }else {
	last_pos := strings.LastIndex(stdout, "/")
	if last_pos > 0 {
	    configPath = stdout[:last_pos]
	    if configPath != "" { return configPath }
	}
    }
    //路径3，GOPATH/src/github.com/hyperledger/fabric/sampleconfig
    configPath, err = fcoreconfig.GetDevConfigDir()
    if err == nil { return configPath }
    //路径4，/etc/hyperledger/fabric
    configPath = fcoreconfig.OfficialPath

    return configPath
}

//参数同getContainerIDs
//env_prefix为搜索过滤容器环境变量的前缀关键字，如orderer容器的ORDERER，peer容器的CORE
//include_key，exclude_key作为搜索现有容器信息的关键字，详看getContainerIDs释义
func getContainersInfo (lastStartContainerTime, env_prefix, include_key1, include_key2 string, exclude_keys... string) []*containerInfo {
    containerIDs := getContainerIDs(include_key1, include_key2, exclude_keys...)

    var containersInfo []*containerInfo
    for _, containerID := range containerIDs {
	//获取容器信息
	//strcmd := fmt.Sprintf("docker inspect --format='{{.State.StartedAt}}|{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.WorkingDir}}|{{.Config.Cmd}}|{{.HostConfig.Binds}}|{{range $cp, $hp := .NetworkSettings.Ports}}{{range $index,$value := $hp}}{{range $hostkey,$hostvalue := $value}}{{if eq $hostkey \"HostPort\"}}{{$hostvalue}}{{end}}{{end}}{{end}}:{{$cp}}+{{end}}|{{range $netkey, $net := .NetworkSettings.Networks}}{{$netkey}}+{{end}}|{{.Config.Labels}}|{{.Config.Image}}|' %s", containerID)
	strcmd := fmt.Sprintf("docker inspect --format='{{.State.StartedAt}}|{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.WorkingDir}}|{{.Config.Cmd}}|{{.HostConfig.Binds}}|{{range $cp, $hp := .NetworkSettings.Ports}}{{range $index,$value := $hp}}{{range $hostkey,$hostvalue := $value}}{{if eq $hostkey \"HostPort\"}}{{$hostvalue}}{{end}}{{end}}{{end}}:{{$cp}}+{{end}}|{{.HostConfig.NetworkMode}}|{{.Config.Labels}}|{{.Config.Image}}|' %s", containerID)
	stdout, stderr, err := doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("docker inspect --format获取容器[%s]信息失败, stderr: %s\n", containerID, stderr)
	    continue
	}

	infos := strings.Split(stdout,"|")
	if len(infos) < 12 {
	    logger.Printf("docker inspect --format获取容器[%s]信息失败\n", containerID)
	    continue
	}

	ci := &containerInfo{}

	//startedAt 2018-04-27T09:18:55.44579463Z
	if infos[0] != "" {
	    ci.startedAt = infos[0][:strings.Index(infos[0], ".")]
	}else {
	    logger.Printf("获取容器[%s]启动时间信息失败\n", containerID)
	    continue
	}
	//当lastStartContainerTime不为空，则说明上次配置存在未成功更新的容器
	//若容器的启动时间在上次更新时间点之后，则说明该容器是上次更新成功了的，当次配置不予配置
	if lastStartContainerTime != "" {
	    currentContainerTime, err := time.Parse("2006-01-02T15:04:05", infos[0])
	    LSCT, err := time.Parse("20060102150405", lastStartContainerTime)
	    if err != nil || currentContainerTime.After(LSCT) {
		logger.Printf("容器[%s]启动时间:%s，LSCT:%s,此次更新略过\n", containerID, currentContainerTime.Format("2006-01-02 15:04:05"), LSCT.Format("2006-01-02 15:04:05"))
		continue
	    }
	}
	//ID ec384aff4481ea460227e8c7e256a17dcd97605a9063553e8b1d113bbeda5f2a
	if infos[1] != "" {
	    ci.id = infos[1]
	}else{
	    logger.Printf("获取容器[%s]完整ID失败\n", containerID)
	    continue
	}
	//Name /orderer.example.com
	if infos[2] != "" {
	    ci.name = infos[2][1:]
	}else{
	    logger.Printf("获取容器[%s]名字失败\n", containerID)
	    continue
	}
	//Image sha256:b17741e7b036bd8a69eb27fc771abeb237b9cba8feab4b420009f084b30eb3f5
	if infos[3] != "" {
	    imageid := strings.Split(infos[3], ":")
	    if len(imageid) < 2 || imageid[1] == "" {
		logger.Printf("获取容器[%s]镜像ID失败\n", containerID)
		continue
	    }
	    ci.imageID = imageid[1]
	}else{
	    logger.Printf("获取容器[%s]镜像ID失败\n", containerID)
	    continue
	}
	//configPath
	ci.configPath = getOneValidOrdererConfigPath(containerID)
	//environments 
	//ORDERER_GENERAL_LOCALMSPID=OrdererMSP
	//ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
	strcmd = fmt.Sprintf("docker exec %s env | grep %s", containerID, env_prefix)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil || stdout == "" {
	    logger.Printf("获取容器[%s]环境变量失败: stderr: %s\n", containerID, stderr)
	    continue
	}else {
	    envPairs := strings.Split(stdout, "\n")
	    envNum := len(envPairs) - 1 //最后一行的\n若Splic后会多出来一个空的
	    if envNum < 1 {
		logger.Printf("获取容器[%s]环境变量失败\n", containerID)
		continue
	    }else{
		ci.environments = make([]string, envNum)
		for i := 0; i < envNum; i++ {
		    //如ORDERER_GENERAL_LOCALMSPID=OrdererMSP
		    ci.environments[i] = envPairs[i]
		}
	    }
	}
	//working_dir /opt/gopath/src/github.com/hyperledger/fabric
	if infos[4] != "" {
	    ci.working_dir = infos[4]
	}else {
	    logger.Printf("获取容器[%s]工作目录失败\n", containerID)
	    continue
	}
	//command [orderer]
	if infos[5] != "" {
	    infos[5] = infos[5][1:(len(infos[5]) - 1)]
	    ci.command = infos[5]
	}else {
	    logger.Printf("获取容器[%s]启动命令失败\n", containerID)
	    continue
	}
	//volumes [/home/wyz/fabric/tls:/var/tls:rw ...]
	if infos[6] != "" {
	    if strings.Index(infos[6],"[") < 0 {
		ci.volumes = make([]string, 1)
		ci.volumes[0] = infos[6]
	    }else {
		//去除开头结尾的[]号
		infos[6] = infos[6][1:(len(infos[6]) - 1)]
		vols := strings.Split(infos[6], " ")
		volNum := len(vols)
		if volNum < 1 {
		    logger.Printf("获取容器[%s]数据卷信息失败\n", containerID)
		    continue
		}
		ci.volumes = make([]string, volNum)
		for i := 0; i < volNum; i++ {
		    //去除最后一个:后的rw
		    ci.volumes[i] = vols[i][:strings.LastIndex(vols[i], ":")]
		}
	    }
	}else {
	    logger.Printf("获取容器[%s]数据卷信息失败\n", containerID)
	    continue
	}
	//ports 8051:7051/tcp+8053:7053/tcp+
	if infos[7] != "" {
	    ports := strings.Split(infos[7], "+")
	    portNum := len(ports) - 1
	    if portNum < 1 {
		logger.Printf("获取容器[%s]端口信息失败\n", containerID)
		continue
	    }
	    ci.ports = make([]string, portNum)
	    for i := 0; i < portNum; i++ {
		//8051:7051/tcp
		diagonal_pos := strings.Index(ports[i], "/")
		ci.ports[i] = ports[i][:diagonal_pos]
	    }
	}else {
	    logger.Printf("获取容器[%s]端口信息失败\n", containerID)
	    continue
	}
	//networks net_byfn1+net_byfn2+
	/*
	if infos[8] != "" {
	    nets := strings.Split(infos[8], "+")
	    //去掉最后一个空值
	    nets = nets[:len(nets) - 1]
	    netNum := len(nets)
	    ci.networks = make([]string, netNum)
	    for inet, net := range nets {
		netNum = strings.Index(net, "_")
		if netNum < 0 {
		    ci.networks[inet] = net
		}else {
		    ci.networks[inet] = net[netNum+1:]
		}
	    }
	}else {
	    logger.Printf("获取容器[%s]网络信息失败\n", containerID)
	    continue
	}
	*/
	if infos[8] != "" {
	    ci.networkMode = infos[8]
	}else {
	    logger.Printf("获取容器[%s]网络信息失败\n", containerID)
	    continue
	}

	//service map[com.xx:1 com.xxx:False com.xxx:net com.docker.compose.service:peer1.org1.example.com ...]
	if infos[9] != "" {
	    //去除map[]
	    infos[9] = infos[9][4: (len(infos[9]) - 1)]
	    coms := strings.Split(infos[9], " ")
	    for _, com := range coms {
		kvp := strings.Split(com, ":")
		if len(kvp) < 2 || kvp[1] == "" { continue }
		if kvp[0] == "com.docker.compose.service" {
		    ci.service = kvp[1]
		    break
		}
	    }
	    if ci.service == "" {
		logger.Printf("获取容器[%s]服务信息失败\n", containerID)
		continue
	    }
	}else {
	    logger.Printf("获取容器[%s]服务信息失败\n", containerID)
	    continue
	}
	//imageName
	if infos[10] != "" {
	    ci.imageName = infos[10]
	}else {
	    logger.Printf("获取容器[%s]镜像名称信息失败\n", containerID)
	    continue
	}
	/*
	//changes
	//C /opt
	//A /opt/gopath
	strcmd = fmt.Sprintf("docker diff %s", containerID)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil || stdout == "" {
	    return nil, logger.Println("获取容器[%s]变动信息失败: stderr: %s", containerID, stderr)
	}
	changedInfos := strings.Split(stdout, "\n")
	changedNum := len(changedInfos) - 1
	ci.changes = make([]string, changedNum)
	for i := 0; i < changedNum; i++ {
	    ci.changes[i] = changedInfos[i]
	}
	*/
	ci.dealState = GettedCurrentContainerInfo
	containersInfo = append(containersInfo, ci)
    }//for end

    return containersInfo
}

//TODO:将散落在各个函数中的对新配置字段的检查都集中到这里进行
func inspectNewConfigData(v *viper.Viper, config_name string) error {
    if v == nil || config_name == "" {
	return fmt.Errorf("inspectNewConfigData error: args is illegal")
    }
    if config_name == "orderer.yaml" {
	//检查端口是否被占用
	if v.IsSet("General.ListenPort") {
	    port := v.GetInt("General.ListenPort")
	    if port == 0 {
		return fmt.Errorf("inspectNewConfigData error: port[%d] is illegal", port)
	    }
	    //查看端口是否被占用
	    strcmd := fmt.Sprintf(`netstat -anp | grep  "\<%d\>"`, port)
	    stdout, stderr, err := doCommand("bash", "-c", strcmd)
	    if err != nil {
		return fmt.Errorf("inspectNewConfigData error: 查询端口[%d]状态失败, stderr: %s", port, stderr)
	    }
	    if stdout != "" {
		return fmt.Errorf("inspectNewConfigData error: 端口[%d]已被占用, stdout: %s", port, stdout)
	    }
	}
	//检查其他
	//...
    }

    return nil
}

//将配置数据写入pathForTempData
//写入的文件在copyConfigFileToConfigPath执行后会被删除
func writeNewConfigDataToPathForTempData(data []byte, configName string, cis []*containerInfo) *viper.Viper {
    if data == nil {
	logger.Println("writeNewConfigDataToPathForTempData error: args is illegal")
	return nil
    }
    if cn := strings.Split(configName, "."); len(cn) < 2 || cn[1] != "yaml" {
	logger.Println("writeNewConfigDataToPathForTempData error: configName is illegal")
	return nil
    }

    v := viper.New()
    v.AddConfigPath(pathForTempData)
    v.SetConfigType("yaml")

    err := v.ReadConfig(bytes.NewBuffer(data))
    if err != nil {
	logger.Printf("Fatal error: %s\n", err)
	return nil
    }
    //TODO:检查配置
    //inspectNewConfigData

    //写入从客户端传来的配置数据
    err = v.WriteConfigAs(fmt.Sprintf("%s/%s", pathForTempData, configName))
    if err != nil {
	logger.Printf("Fatal error:写配置文件到当前目录失败: %s\n", err)
	return nil
    }

    for i, ci := range cis {
	if ci.dealState < GettedCurrentContainerInfo { continue }
	cis[i].dealState = WrittedConfigDataToFile
    }

    return v
}

//把配置文件复制到当前容器，然后删除当前目录下和容器数据卷对应的主机目录下的配置文件
func copyConfigFileToConfigPath(configName string, cis []*containerInfo) {
    if configName == "" || len(cis) == 0 {
	logger.Println("copyConfigFileToConfigPath: error: args is illegal")
	return
    }

    var stderr, strcmd string
    var err error
    for i, ci := range cis {
	if ci.dealState < WrittedConfigDataToFile || ci.configPath == "" { continue }

	//示例：docker cp /var/meserver/orderer.yaml ec38:/root
	strcmd = fmt.Sprintf("docker cp %s/%s %s:%s", pathForTempData, configName, ci.id, ci.configPath)
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("copyConfigFileToConfigPath error: %s stderr: %s\n", err, stderr)
	    continue
	}

	cis[i].dealState = CopiedConfigFileToCurrentContainer
    }

    strcmd = fmt.Sprintf("rm -f %s/%s", pathForTempData, configName)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Printf("删除临时生成的配置文件%s失败\n", stderr, configName)
    }
}

//
func dockerCommitAndStopAndDelteCurrentContainer(cis []*containerInfo) {
    if cis == nil || len(cis) == 0 {
	logger.Println("dockerCommitAndStopAndDelteCurrentContainer error: args is illegal")
	return
    }
    var timestamp, strcmd, stdout, stderr string
    var err error
    for i, ci := range cis {
	if ci.dealState < CopiedConfigFileToCurrentContainer { continue }
	//1.将原容器对应的latest tag为时间戳 , 然后从现有容器 commit出新的latest镜像
	timestamp = time.Now().Format("20060102150405")
	strcmd = fmt.Sprintf("docker tag %s:latest %s:%s", ci.imageName, ci.imageName, timestamp)
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("docker tag failed[strcmd: %s], stderr: %s\n", strcmd, stderr)
	    continue
	}
	//docker commit -a "meserver" -m "time:meserver committed from orderer" a404c6c174a2  mymysql:v1
	strcmd = fmt.Sprintf("docker commit -a \"MEServer\" -m \"MEServer committed from container[%s] at %s\" %s %s:latest", ci.id, timestamp, ci.id, ci.imageName)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil || stdout == "" {
	    logger.Printf("docker commit failed[strcmd: %s], stderr: %s\n", strcmd, stderr)
	    //若没有成功，则继续，统一由meserver的启动时间点来鉴别未成功处理的容器
	    continue
	}
	cis[i].dealState = CommittedCurrentContainer
	//记录由现容器生成的新的镜像ID
	cis[i].imageIDForDockerCommit = strings.TrimRight(strings.Split(stdout, ":")[1], "\n")

	//2.stop and delete - 测试时注销此步
	strcmd = fmt.Sprintf("docker rm -f %s", ci.id)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	//如果删除现有容器失败，则删除刚刚创建的新image
	if err != nil {
	    logger.Printf("docker rm -f container[%s] failed\n", ci.id)
	    strcmd = fmt.Sprintf("docker rmi -f %s", cis[i].imageIDForDockerCommit)
	    _, _, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("删除原容器失败后，删除新生成的镜像失败")
	    }
	    continue
	}
	cis[i].dealState = DeleteCurrentContainer
    }
}

//更新环境变量，主要是环境变量
//该viper为读取了新的配置的viper
//prefix为环境变量的前缀
//原则：新配置中未设定的项，则使用原容器中的值，即旧值
func updateContainerInfo(prefix string, v *viper.Viper, cis []*containerInfo) {
    if prefix == "" || v == nil || cis == nil || len(cis) == 0 {
	logger.Println("updateContainerInfo error: args is illegal")
	return
    }
    prefixLen := len(prefix)
    incremental_factor := 10
    var next bool

    for i, ci := range cis {
	if ci.dealState < DeleteCurrentContainer { continue }
	next = false

	for n, one := range ci.environments {
	    //环境变量 ORDERER_GENERAL_LOCALMSPID=OrdererMSP
	    // CORE_PEER_ID=peer0.org1.example.com
	    if strings.HasPrefix(one, prefix) == false { continue }
	    kv := strings.Split(one, "=")
	    if len(kv) < 2 || kv[1] == "" {
		logger.Printf("updateContainerInfo error: environment[%s] is ill\n", one)
		next = true
		break
	    }
	    //ORDERER_GENERAL_LOCALMSPID -> GENERAL.LOCALMSPID
	    k := strings.Replace(kv[0][prefixLen + 1:], "_", ".", -1)
	    //如果设置了该项，则更新为新值
	    if v.IsSet(k) {
		nv := v.Get(k)
		switch nv.(type) {
		case string:
		    cis[i].environments[n] = fmt.Sprintf("%s=%s", kv[0], nv.(string))
		case bool:
		    cis[i].environments[n] = fmt.Sprintf("%s=%s", kv[0], strconv.FormatBool(nv.(bool)))
		case float64:
		    cis[i].environments[n] = fmt.Sprintf("%s=%f", kv[0], nv.(float64))
		case int:
		    cis[i].environments[n] = fmt.Sprintf("%s=%d", kv[0], nv.(int))
		case []interface{}:
		    cis[i].environments[n] = fmt.Sprintf("%s=[", kv[0])
		    smallnum := 0
		    for _, smallone := range nv.([]interface{}) {
			if smallone == nil { continue }
			smallnum++
			cis[i].environments[n] += fmt.Sprintf("%v ", smallone)
		    }
		    //如果没有有效的数组元素，即数组里都是null值，则认定新配置未设定此环境变量，则使用旧值
		    //TODO:另一只方案是从cis[i].environments中删除该环境变量
		    if smallnum == 0 {
			/*
			//上述TODO所述的另一种方案
			if n == len(cis[i].environments) - 1 {
			    cis[i].environments = cis[i].environments[:n]
			}else {
			    cis[i].environments = append(cis[i].environments[:n], cis[i].environments[n+1:]...)
			}
			*/
			cis[i].environments[n] = fmt.Sprintf("%s=%s", kv[0], kv[1])
		    }else{
			smallnum = len(cis[i].environments[n]) - 1
			cis[i].environments[n] = cis[i].environments[n][:smallnum]
			cis[i].environments[n] += "]"
		    }
		default:
		    logger.Println("updateContainerInfo error: unknown type of env's value")
		    next = true
		    break
		}
	    }else {
		//若新配置未设置该项环境变量，使用旧值
		//TODO:另一种方案是删除该环境变量，则在此删除
	    }
	}

	if next { continue }

	//端口, 直接换成新配置数据里的信息
	//orderer有两个端口可配置
	if prefix == "ORDERER" {
	    //orderer只有一个端口 7050:7050 ????
	    if v.IsSet("General.ListenPort") {
		binds := strings.Split(ci.ports[0], ":")
		np :=  v.GetInt("General.ListenPort")
		if np == 0 {
		    logger.Println("updateContainerInfo error: General.ListenPort is wrong")
		    continue
		}
		cis[i].ports[0] = binds[0] + ":" + fmt.Sprintf("%d", np)
	    }

	    if v.IsSet("General.Profile.Enabled") && v.GetBool("General.Profile.Enabled") {
		nv := v.Get("General.Profile.Address").(string)
		if nv == "" {
		    logger.Println("updateContainerInfo error: General.Profile.Address is wrong")
		    continue
		}
		np := strings.Split(nv, ":")
		if len(np) < 2 || np[1] == "" {
		    logger.Println("updateContainerInfo error: Port of General.Profile.Address is wrong")
		    continue
		}
		containerPort, err := strconv.Atoi(np[1])
		if err != nil {
		    logger.Println("updateContainerInfo error: Port of General.Profile.Address is wrong")
		    continue
		}

		if len(ci.ports) == 1 {
		    //增加一个新的主机端口
		    //主机端口为 容器端口号+增数因子（每个容器间端口号在容器端口的基础上"累加"10）
		    //比如容器1为 7053:7053, 容器2就可能为7063:7053
		    //端口号尝试增加incremental_factor次，寻找一个不被占用的
		    //若寻找不到，再让容器自己随机分配
		    var stdout, stderr, strcmd string
		    hostPort := (containerPort + i*incremental_factor)
		    count := 0
		    for count = 0; count < incremental_factor; count++ {
			strcmd = fmt.Sprintf(`netstat -anp | grep  "\<%d\>"`, hostPort+count)
			stdout, stderr, err = doCommand("bash", "-c", strcmd)
			if err != nil {
			    logger.Printf("updateContainerInfo error: 查询端口[%d]是否被占用出错, stderr: %s\n", hostPort+count, stderr)
			    continue
			}
			if stdout == "" { break }
		    }
		    if count == incremental_factor {
			//随机分配
			cis[i].ports = append(cis[i].ports, np[1])
		    }else {
			//指定分配
			cis[i].ports = append(cis[i].ports, fmt.Sprintf("%d:%d", hostPort+count, containerPort))
		    }
		}else {
		    binds := strings.Split(ci.ports[1], ":")
		    if len(binds) < 2 {
			logger.Println("updateContainerInfo error: ci.ports[1] is wrong")
			continue
		    }
		    cis[i].ports[1] = binds[0] + ":" + np[1]
		}
	    }
	}else {
	    //PEER
	}

	cis[i].dealState = UpdatedContainerInfo
    }//for end
}

//新生成的docker compose file均以现有容器的id命名
func writeTempDockerComposeFileByCurrentContainerInfo( cis []*containerInfo ) {
    if cis == nil || len(cis) == 0 {
	logger.Println("writeTempDockerComposeFileByCurrentContainerInfo error: args is illegal")
	return
    }

    for i, ci := range cis {
	if ci.dealState < UpdatedContainerInfo { continue }

	v := viper.New()
	v.AddConfigPath(pathForTempData)
	v.SetConfigType("yaml")
	v.Set("version", "2")
	/*
	for _, net := range ci.networks {
	    //BUVIDKWZUFMEYBKSYNHK - '不知道为什么有空引号'的双拼字母
	    //在下文会使用sed命令替换为空
	    v.Set(fmt.Sprintf("networks.%s", net), "BUVIDKWZUFMEYBKSYNHK")
	}
	*/
	//由于viper的key中无法有.，但fabric服务名、容器名都是xxx.xxx.xxx格式的
	//因此这里先用一个假名代替，. 先由占位符|_|替代
	serverAliasName := strings.Replace(ci.service, ".", csshare.SEPARATOR, -1)
	serverPrefix := fmt.Sprintf("services.%s.", serverAliasName)
	v.Set(serverPrefix + "container_name", strings.Replace(ci.name, ".", csshare.SEPARATOR, -1))
	v.Set(serverPrefix + "image", ci.imageName)
	v.Set(serverPrefix + "environment", ci.environments)
	v.Set(serverPrefix + "working_dir", ci.working_dir)
	v.Set(serverPrefix + "command", ci.command)
	//v.Set(serverPrefix + "networks", ci.networks)
	v.Set(serverPrefix + "network_mode", ci.networkMode)
	v.Set(serverPrefix + "volumes", ci.volumes)
	v.Set(serverPrefix + "ports", ci.ports)

	err := v.WriteConfigAs(fmt.Sprintf("%s/%s.yaml", pathForTempData, ci.id))
	if err != nil {
	    logger.Printf("生成docker compose文件[%s.yaml]失败\n", ci.id)
	    continue
	}
	//使用sed命令替换占位符|_|和BUVIDKWZUFMEYBKSYNHK
	//TODO:在MacOSX上sed命令单纯的-i会存在问题
	strcmd := fmt.Sprintf(`sed -i -e "s/%s/./g" -e "s/BUVIDKWZUFMEYBKSYNHK//g" %s/%s.yaml`, csshare.SEPARATOR, pathForTempData, ci.id)
	_, stderr, err := doCommand("bash", "-c", strcmd)
	if err != nil {
	    //删除刚刚写的文件
	    strcmd := fmt.Sprintf("rm -f %s/%s", pathForTempData, ci.id)
	    doCommand("bash", "-c", strcmd)
	    logger.Printf("替换文件[%s.yaml]中占位字符失败: stderr: %s\n", ci.id, stderr)
	    continue
	}

	cis[i].dealState = WrittedDockerComposeFile
    }
}

func dockerComposeUpNewContainer(cis []*containerInfo) {
    if cis == nil || len(cis) == 0 {
	logger.Println("dockerComposeUpNewContainer error: args is illegal")
	return
    }

    var stdout, stderr, strcmd string
    var err error
    for i, ci := range cis {
	if ci.dealState < WrittedDockerComposeFile { continue }

	strcmd = fmt.Sprintf("docker-compose -f %s/%s.yaml up -d 2>&1", pathForTempData, ci.id)
	stdout, _, err = doCommand("bash", "-c", strcmd)
	if err != nil || strings.Index(stdout, "done") < 0 {
	    logger.Printf("docker-compose -f %s/%s.yaml up -d error, stderr: %s\n", pathForTempData, ci.id, stdout)
	    continue
	}
	cis[i].dealState = RanNewContainer //只要走到这一步，就算成功
	strcmd = fmt.Sprintf("rm -f %s/%s.yaml", pathForTempData, ci.id)
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("rm -f %s/%s.yaml error, stderr: %s\n", pathForTempData, ci.id, stderr)
	    continue
	}
	//形式主义
	cis[i].dealState = CleanedTempData
	cis[i].dealState = AllDone
    }
}


//暂时用不到
func restartContainer(containerID string) error {
    strcmd := fmt.Sprintf("docker restart %s", containerID)
    stdout, stderr, err := doCommand("bash", "-c", strcmd)
    if err != nil {
	return fmt.Errorf("doCommand error: %s", stderr)
    }
    fmt.Printf("container[%s]: restarted success: %s\n", containerID, stdout)
    return nil
}

func reportUpdateResults(cis []*containerInfo) (string, bool) {
    if cis == nil || len(cis) == 0 {
	logger.Println("reportUpdateResult error: args is illegal")
	return "reportUpdateResult error: args is illegal", false
    }
    var result, results string
    var errNum int = 0
    results = "\n节点容器ID\t更新结果\t详细情况\n"
    for _, ci := range cis {
	if ci.dealState < RanNewContainer {
	    result = fmt.Sprintf("[%s]\t失败\t[%s]完成后，执行[%s]失败\n", ci.id[:8], STEPS_EXPLAIN[ci.dealState], STEPS_EXPLAIN[ci.dealState+1])
	    errNum++
	}else {
	    if ci.dealState < AllDone {
		result = fmt.Sprintf("[%s]\t成功\t未将临时文件清除\n", ci.id[:8])
	    }else {
		result = fmt.Sprintf("[%s]\t成功\t%s\n", ci.id[:8], STEPS_EXPLAIN[AllDone])
	    }
	}
	results += result
    }
    results += fmt.Sprintf("统计：%d个节点升级成功，%d个节点升级失败\n", len(cis) - errNum, errNum)
    return results, errNum == 0
}

//返回的每一个string的格式为containerName|_|containerID|_|是否开启TLS|_|channelA,channelB
//由于每一个string都要分割后显示在orderer.gui.go->listAndDisplayGroup->listChannel中，因此
//分割后的slice数量与orderer.gui.go->listAndDisplayGroup->listChannelColumn相同
func getPeerChannelBasicInfo() []string {
    //使用peer容器启动命令peer node start作为关键字，搜索peer容器节点
    peerContainerIDs := getContainerIDs("peer node start", "", "grep")
    if len(peerContainerIDs) == 0 {
	return nil
    }

    var result string
    var results []string
    var stdout, stderr, strcmd string
    var err error
    var num int
    for _, id := range peerContainerIDs {
	//节点名称-节点ID
	strcmd = fmt.Sprintf("docker ps --filter='id=%s' --format='{{.Names}}%s{{.ID}}%s'", id, csshare.SEPARATOR, csshare.SEPARATOR)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("获取容器[%s]基本信息失败: stderr: %s\n", id, stderr)
	    //当基本信息都获取不了，则直接略过
	    continue
	}
	result = strings.TrimRight(stdout, "\n")
	//通过容器环境变量查看是否开启了TLS
	strcmd = fmt.Sprintf("docker exec %s env | grep %s", id, CORE_PEER_TLS_ENABLED_ENV_KEY)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Printf("获取容器[%s]环境变量CORE_PEER_TLS_ENABLED失败: stderr: %s\n", id, stderr)
	    result += fmt.Sprintf("查询失败%s", csshare.SEPARATOR)
	}else {
	    if strings.Index(stdout, "true") < 0 {
		result += fmt.Sprintf("false%s", csshare.SEPARATOR)
	    }else{
		result += fmt.Sprintf("true%s", csshare.SEPARATOR)
	    }
	}
	//peer list查看节点所加入的channel
	//若正常查出，则在结尾后缀上(*^_^*)符号组合，已供查询channel详细信息 的时候进行辨别显示的是正常的channel
	if metadata.FabricVersion == "1.0" {
	    //注意：
	    //1.0是以日志的形式打出的peer节点所加入的channel信息
	    //而根据fabric/common/flogging/logging.go中的 defaultOutput = os.Stderr，即fabric中日志打印默认是
	    //打印在标准错误输出的，因此是channel的信息是在stderr中的。
	    //使用用2>&1将消息重定向到标准输出，此时通过管道进行grep操作，若grep未搜索出结果，则返回码是错误的，
	    //因此无法辨别错误与无channel时的情况
	    //对输出的channelID的处理-对看fabric源码的peer/channel/list.go中'list'函数所对channelID输出的格式
	    strcmd = fmt.Sprintf("docker exec %s peer channel list 2>&1 | grep 'list' | grep -v 'Channels peers has joined to' ", id)
	    stdout, _, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Printf("获取容器[%s]peer节点所加入的channel失败: stderr: %s, err:%s\n", id, stderr, err)
		result += "未加入channel或查询错误"
	    }else {
		/*
		v1.0版的输出代码如下
		logger.Infof("Channels peers has joined to: ")
		for _, channel := range channels {
		    logger.Infof("%s ", channel.ChannelId)
		}
		格式如下
		2018-05-11 02:53:23.904 UTC [channelCmd] list -> INFO 007 mychannel \n
		2018-05-11 02:53:23.904 UTC [channelCmd] list -> INFO 007 mychannel2 \n
		*/
		channels := strings.Split(stdout, "\n")
		num = len(channels)
		if num < 2 {
		    logger.Printf("容器[%s]peer channel list输出结果[%s]与预期不符\n", id, stdout)
		    result += "查询失败"
		}else {
		    //每行都有\n，因此Split之后最后一个是空值，因此删除最后一个空值
		    num -= 1
		    channels = channels[:num]
		    num -= 1
		    for i, channel := range channels {
			//删除最后一个空格，然后定位最后一个空格（后边就是channelID）
			channel = strings.TrimRight(channel, " ")
			pos := strings.LastIndex(channel, " ") + 1
			if i != num {
			    result += (channel[pos:] + ",")
			}else {
			    result += channel[pos:]
			}
		    }
		    result += "(*^_^*)"
		}
	    }
	}else if metadata.FabricVersion == "1.1" {
	    strcmd = fmt.Sprintf("docker exec %s peer channel list | grep list | grep -v 'Channels peers has joined to'", id)
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Printf("获取容器[%s]peer节点所加入的channel失败: stderr: %s, err:%s\n", id, stderr, err)
		result += "查询失败"
	    }else if stdout == "" {
		//没有加入任何channel
		result += "无"
	    }else {
		/*
		v1.1版输出代码如下
		fmt.Println("Channels peers has joined: ")
		for _, channel := range channels {
		    fmt.Printf("%s\n", channel.ChannelId)
		}
		格式如下
		mychannel\n
		mychannel2\n
		默认按1.0输出
		*/
		channels := strings.Split(stdout, "\n")
		num = len(channels)
		if num < 2 {
		    logger.Printf("容器[%s]peer channel list输出结果[%s]与预期不符", id, stdout)
		    result += "查询失败"
		}else {
		    //去掉最后一个空的
		    num -= 1
		    channels = channels[:num]
		    num -= 1
		    for i, channel := range channels {
			if i != num {
			    result += (channel + ",")
			}else {
			    result += channel
			}
		    }
		    result += "(*^_^*)"
		}
	    }
	}else {
	    //其他版本暂不支持
	    result += "暂不支持的fabric版本"
	}

	results = append(results, result)
    }
    /*
    for _, one := range results {
	logger.Println("获取channelInfo -", one)
    }
    */
    strcmd = fmt.Sprintf("rm -f %s/*.block", pathForTempData)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("清理临时*.block文件失败，stderr: %s, err: %s\n", stderr, err)
    }

    return results
}

//toolpath为configtxlator所在的路径
func startConfigtxlator(toolpath string) *os.Process {
    var configtxlator *os.Process
    var stdout, stderr, strcmd string
    var err error
    strcmd = fmt.Sprintf("ps -ef | grep '%s start' | grep -v 'grep' | awk '{print $2}' ", toolpath)
    stdout, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("ps -ef错误，stderr: %s, err: %s\n", stderr, err)
	return nil
    }else {
	if stdout == "" {
	    //未开启，则开启
	    ctlARGS := []string{tool_CONFIGTXLATOR, "start"}
	    ctlPA := &os.ProcAttr{Files:[]*os.File{os.Stdin,os.Stdout,os.Stderr}}
	    configtxlator, err = os.StartProcess(tool_CONFIGTXLATOR, ctlARGS, ctlPA)
	    if err != nil {
		logger.Printf("configtxlator启动失败, err: %s\n", err)
		return nil
	    }
	}else {
	    //已开启，则查找进程对象
	    stdout = strings.Trim(stdout, "\n")
	    pid, err := strconv.Atoi(stdout)
	    if err != nil {
		logger.Printf("转换configtxlator程序PID[%s]失败, err: %s\n", stdout, err)
		return nil
	    }
	    configtxlator, err = os.FindProcess(pid)
	    if err != nil {
		logger.Printf("获取configtxlator进程对象失败, err: %s\n", err)
		return nil
	    }
	}
    }

    return configtxlator
}

func killConfigtxlator(configtxlator *os.Process) error {
    if configtxlator == nil {
	return fmt.Errorf("configtxlator is nil")
    }
    return configtxlator.Kill()
}

//data格式:
//1.容器ID|_|OrdererIP:端口|_|channelIDs|_|CA路径
//2.容器ID1|_|OrdererIP:端口|_|channelIDs
func getPeerChannelDetailInfo(data string) []*csshare.ChannelInfo {
    ordererInfos := strings.Split(data, csshare.SEPARATOR)
    //num == 3 - 未开启TLS， == 4 - 开启了TLS
    num := len(ordererInfos)
    if num != 3 && num != 4 {
	logger.Println("获取节点所持Orderer节点CA证书路径不符预期")
	return nil
    }

    var stdout, stderr, strcmd string
    var err error
    //与getPeerChannelBasicInfo()中获取channelID时的分隔符一致
    channelIDs := strings.Split(ordererInfos[2], ",")

    var results []*csshare.ChannelInfo
    var slices []string
    var cv csshare.ConfigValue
    //1.获取最新配置block
    //2.复制出来到pathForTempData中，转换成json，并从容器中删除
    //3.根据block摘取通道信息，拼接一条字符串
    //开启configtxlator，若已开启，则不重复开启
    configtxlator := startConfigtxlator(tool_CONFIGTXLATOR)
    if configtxlator == nil {
	logger.Println("启动configtxlator失败")
	return nil
    }

    //遍历每个通道的数据
    for _, channelID := range channelIDs {
	result := &csshare.ChannelInfo{ChannelID: channelID}
	if metadata.FabricVersion == "1.0" {
	    //1.
	    if num == 3 {
		strcmd = fmt.Sprintf("docker exec %s peer channel fetch config  /%s_config_newest.block -o %s -c %s",
		    ordererInfos[0], ordererInfos[0], ordererInfos[1], channelID)
	    }else {
		strcmd = fmt.Sprintf("docker exec %s peer channel fetch config /%s_config_newest.block -o %s -c %s --tls --cafile %s",
		    ordererInfos[0], ordererInfos[0], ordererInfos[1], channelID, ordererInfos[3])
	    }
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行peer channel fetch config错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }

	    if num == 3 {
		strcmd = fmt.Sprintf("docker exec %s peer channel fetch oldest /%s_config_genesis.block -o %s -c %s",
		    ordererInfos[0], ordererInfos[0], ordererInfos[1], channelID)
	    }else {
		strcmd = fmt.Sprintf("docker exec %s peer channel fetch oldest /%s_config_genesis.block -o %s -c %s --tls --cafile %s",
		    ordererInfos[0], ordererInfos[0], ordererInfos[1], channelID, ordererInfos[3])
	    }
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行peer channel fetch oldest错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }
	    //2.
	    strcmd = fmt.Sprintf("docker cp %s:/%s_config_newest.block %s && docker exec %s rm -f /%s_config_newest.block",
		ordererInfos[0], ordererInfos[0], pathForTempData, ordererInfos[0], ordererInfos[0])
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行docker cp newest && docker exec rm -f错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }
	    strcmd = fmt.Sprintf("docker cp %s:/%s_config_genesis.block %s && docker exec %s rm -f /%s_config_genesis.block",
		ordererInfos[0], ordererInfos[0], pathForTempData, ordererInfos[0], ordererInfos[0])
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行docker cp genesis && docker exec rm -f错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }
	    //使用configtxlator将block转为json
	    //只截取需要的内容：newest只保留.data.data[0].payload.data.config, genesis只保留.data.data[0].payload.data.last_update
	    strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_config_newest.block \"http://127.0.0.1:7059/protolator/decode/common.Block\" | %s '.data.data[0].payload.data.config' > %s/%s_config_newest.json", pathForTempData, ordererInfos[0], tool_JQ, pathForTempData, ordererInfos[0])
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行configtxlator newest > json错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }
	    strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_config_genesis.block \"http://127.0.0.1:7059/protolator/decode/common.Block\" | %s '.data.data[0].payload.data.last_update' > %s/%s_config_genesis.json", pathForTempData, ordererInfos[0], tool_JQ, pathForTempData, ordererInfos[0])
	    _, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("节点容器[%s]执行configtxlator genesis > json错误，stderr: %s, err: %s\n", ordererInfos[0], stderr, err)
		results = append(results, result)
		continue
	    }
	    //3.
	    //依次输出: 创建时间、创建者、创建者所持MSPID、创建者签名
	    strcmd = fmt.Sprintf("%s -r '.payload.header.channel_header.timestamp, .payload.header.signature_header.creator.id_bytes, .payload.header.signature_header.creator.mspid, .signature' %s/%s_config_genesis.json", tool_JQ, pathForTempData, ordererInfos[0])
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    slices = strings.Split(stdout, "\n")
	    if err != nil || len(slices) < 5 {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("执行jq -r '' genesis.json错误，stderr: %s, err: %s\n", stderr, err)
		results = append(results, result)
		continue
	    }
	    ct, err := time.Parse("2006-01-02T15:04:05.999Z07:00", slices[0])
	    if err != nil {
		logger.Printf("解析创建日期失败, err: %s\n", err)
		result.CreateTime = fmt.Sprintf("解析失败-%s", slices[0])
	    }else {
		result.CreateTime = ct.Format("2006-01-02 15:04:05")
	    }
	    decoded, err := base64.StdEncoding.DecodeString(slices[1])
	    if err != nil {
		logger.Printf("解析创建者失败, stderr:%s, err: %s\n", stderr, err)
		result.Creator = "解析失败"
	    }else {
		result.Creator = string(decoded)
	    }
	    result.CreatorMspID = slices[2]
	    result.CreatorSignatrue = slices[3]
	    //依次输出: 组织、组织配置值(MSP，AnchorPeers)
	    strcmd = fmt.Sprintf("%s '.channel_group.groups.Application.groups | keys' %s/%s_config_newest.json | grep '\"'",
		tool_JQ, pathForTempData, ordererInfos[0])
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    //jq '... | keys' 取出来的值，每个值的格式如 "Org1"
	    slices = strings.Split(stdout, ",")
	    if err != nil || len(slices) == 0 {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("解析通道包含的组织失败, stderr:%s, err: %s\n", stderr, err)
	    }else {
		result.OrgsInfo = make(map[string]map[string]interface{})
		for _, org := range slices {
		    if org == "" {
			continue
		    }
		    org = strings.Trim(org, " \"\n")
		    result.OrgsInfo[org] = make(map[string]interface{})
		    //AnchorPeers
		    strcmd = fmt.Sprintf("%s '.channel_group.groups.Application.groups.%s.values.AnchorPeers' %s/%s_config_newest.json",
			tool_JQ, org, pathForTempData, ordererInfos[0])
		    stdout, stderr, err = doCommand("bash", "-c", strcmd)
		    if err != nil || stdout == "" {
			logger.Printf("解析组织配置项[锚点]失败, stderr:%s, err: %s\n", stderr, err)
			result.OrgsInfo[org][csshare.CV_AP] = nil
		    }else {
			cv.Value = &csshare.AnchorPeers{}
			err = json.Unmarshal([]byte(stdout), &cv)
			if err != nil {
			    logger.Printf("解析组织配置项[锚点]json结构失败, err: %s\n", err)
			    result.OrgsInfo[org][csshare.CV_AP] = nil
			}else {
			    result.OrgsInfo[org][csshare.CV_AP] = cv.Value
			}
		    }
		    //MSP
		    strcmd = fmt.Sprintf("%s '.channel_group.groups.Application.groups.%s.values.MSP' %s/%s_config_newest.json",
			tool_JQ, org, pathForTempData, ordererInfos[0])
		    stdout, stderr, err = doCommand("bash", "-c", strcmd)
		    if err != nil {
			logger.Println("strcmd: ", strcmd)
			logger.Printf("解析组织配置项[MSP]失败, stderr:%s, err: %s\n", stderr, err)
			result.OrgsInfo[org][csshare.CV_MSP] = nil
		    }else {
			cv.Value = &csshare.MSPConfig{}
			err = json.Unmarshal([]byte(stdout), &cv)
			if err != nil {
			    logger.Printf("解析组织配置项[锚点]json结构失败, err: %s\n", err)
			    result.OrgsInfo[org][csshare.CV_MSP] = nil
			}else {
			    result.OrgsInfo[org][csshare.CV_MSP] = cv.Value
			}
		    }
		}
	    }
	    //通道策略
	    strcmd = fmt.Sprintf("%s '.channel_group.policies | keys' %s/%s_config_newest.json | grep '\"' ",
		tool_JQ, pathForTempData, ordererInfos[0])
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    slices = strings.Split(stdout, ",")
	    if err != nil || len(slices) == 0 {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("解析通道策略keys失败, stderr:%s, err: %s\n", stderr, err)
	    }else {
		result.Policies = make(map[string]string)
		for _, pol := range slices {
		    if pol == "" {
			continue
		    }
		    pol = strings.Trim(pol, " \"\n")
		    strcmd = fmt.Sprintf("%s '.channel_group.policies.%s.policy' %s/%s_config_newest.json",
			tool_JQ, pol, pathForTempData, ordererInfos[0])
		    stdout, stderr, err = doCommand("bash", "-c", strcmd)
		    if err != nil || stdout == "" {
			logger.Println("strcmd: ", strcmd)
			logger.Printf("解析通道策略[%s]失败, stderr:%s, err: %s\n", pol, stderr, err)
			result.Policies[pol] = ""
		    }else {
			result.Policies[pol] = stdout
		    }
		}
	    }
	    //通道配置值(Consortium,OrdererAddresses)
	    result.Config = make(map[string]interface{})
	    strcmd = fmt.Sprintf("%s '.channel_group.values.Consortium' %s/%s_config_newest.json",
		tool_JQ, pathForTempData, ordererInfos[0])
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil || stdout == "" {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("解析通道Consortium失败, stderr:%s, err: %s\n", stderr, err)
		result.Config[csshare.CV_CST] = nil
	    }else {
		cv.Value = &csshare.Consortium{}
		err = json.Unmarshal([]byte(stdout), &cv)
		if err != nil {
		    logger.Printf("解析通道Consortium失败, err: %s\n", err)
		    result.Config[csshare.CV_CST] = nil
		}else {
		    result.Config[csshare.CV_CST] = cv.Value
		}
	    }
	    strcmd = fmt.Sprintf("%s '.channel_group.values.OrdererAddresses' %s/%s_config_newest.json",
		tool_JQ, pathForTempData, ordererInfos[0])
	    stdout, stderr, err = doCommand("bash", "-c", strcmd)
	    if err != nil || stdout == "" {
		logger.Println("strcmd: ", strcmd)
		logger.Printf("解析通道OrdererAddresses失败, stderr:%s, err: %s\n", stderr, err)
		result.Config[csshare.CV_OADDR] = nil
	    }else {
		cv.Value = &csshare.OrdererAddresses{}
		err = json.Unmarshal([]byte(stdout), &cv)
		if err != nil {
		    logger.Printf("解析通道OrdererAddresses失败, err: %s\n", err)
		    result.Config[csshare.CV_OADDR] = nil
		}else {
		    result.Config[csshare.CV_OADDR] = cv.Value
		}
	    }

	}else if metadata.FabricVersion == "1.1" {

	}else {
	    result.CreateTime = "暂不支持的fabric版本"
	    result.Creator = "暂不支持的fabric版本"
	    result.CreatorMspID = "暂不支持的fabric版本"
	    result.CreatorSignatrue = "暂不支持的fabric版本"
	}

	results = append(results, result)
    }//for _, channelID := range channelIDs end

    //清理工作
    err = killConfigtxlator(configtxlator)
    if err != nil {
	logger.Printf("停止configtxlator进程失败, err: %s\n", err)
    }
    //
    strcmd = fmt.Sprintf("rm -f %s/*.json %s/*.block", pathForTempData, pathForTempData)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Printf("清除.block .json临时数据文件失败, stderr: %s, err: %s\n", stderr, err)
    }

    return results
}

//数据由func (ao *addOrgGroup) getConfigurationData()生成
//data 由gob Encode成[]byte
/*
infos := make(map[string][]byte)
infos[csshare.AddOrgSignNodeNum] = ao.signNodeNum
infos[fmt.Sprintf("signnode%d", i)] = ip + csshare.SEPARATOR + containerid + csshare.SEPARATOR + msppath
infos[csshare.AddOrgOrgName] = ao.orgName.Text()
infos[csshare.AddOrgConfigtx] = configtx
infos[csshare.AddOrgCrypto] = crypto
infos[csshare.AddOrgContainerID] = ordererCC.listAndDisplay.listChannel.Item(row, 1).Text()
infos[csshare.AddOrgOrdererIP] = ordererCC.function.ordererIPLineEdit.Text()
infos[csshare.AddOrgChannelID] = ao.channelID.CurrentText()
if tlsEnabled {
    infos[csshare.AddOrgTLSCAPath] = ordererCC.function.caFilePathLineEdit.Text()
}
*/
func addOrgDataToChannelConfig(data []byte) error {

    var tlsEnabled bool
    var path string
    var err error
    var stdout, stderr, strcmd string

    buffer := bytes.NewBuffer(data)
    infos := make(map[string]string)
    err = gob.NewDecoder(buffer).Decode(&infos)
    if err != nil {
	logger.Printf("gob Decode(&infos) failed: %s\n", err)
	return fmt.Errorf("gob Decode(&infos) failed: %s", err)
    }

    _, tlsEnabled = infos[csshare.AddOrgTLSCAPath]

    //1.写入客户端传来的添加的组织数据进configtx.yaml/crypto.yaml
    //由于configtxgen工具的限制，这个文件名只能是configtx.yaml
    path = fmt.Sprintf("%s/configtx.yaml", pathForTempData)
    err  = ioutil.WriteFile(path, []byte(infos[csshare.AddOrgConfigtx]), 0700)
    if err != nil {
	logger.Printf("%s/configtx.yaml写入失败\n", pathForTempData)
	return fmt.Errorf("%s/configtx.yaml写入失败", pathForTempData)
    }
    path = fmt.Sprintf("%s/%s_neworg_crypto.yaml", pathForTempData, infos[csshare.AddOrgContainerID])
    err  = ioutil.WriteFile(path, []byte(infos[csshare.AddOrgCrypto]), 0700)
    if err != nil {
	logger.Printf("%s/%s_neworg_crypto.yaml写入失败\n", pathForTempData, infos[csshare.AddOrgContainerID])
	return fmt.Errorf("%s/%s_neworg_crypto.yaml写入失败\n", pathForTempData, infos[csshare.AddOrgContainerID])
    }
    //2.开启configtxlator
    configtxlator := startConfigtxlator(tool_CONFIGTXLATOR)
    if configtxlator == nil {
	logger.Println("启动configtxlator失败")
	return fmt.Errorf("启动configtxlator失败")
    }

    if metadata.FabricVersion == "1.0" {
	//3.根据configtx.yaml/crypto.yaml生成用于channel升级的artifact
	//生成的组织和组织节点的msp文件必须在crypto-config文件夹下
	//先清除一下，如果已经有这个文件夹了，会输出失败
	strcmd = fmt.Sprintf("rm -rf %s/crypto-config && %s generate --config=%s/%s_neworg_crypto.yaml --output=%s/crypto-config",
	    pathForTempData, tool_CRYPTOGEN, pathForTempData, infos[csshare.AddOrgContainerID], pathForTempData)
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("cryptogen generate错误，stderr: %s, err: %s\n", stderr, err)
	    return fmt.Errorf("cryptogen generate错误，stderr: %s, err: %s\n", stderr, err)
	}
	//命令行中的export FABRIC_CFG_PATH只在当次命令执行中有效
	//FABRIC_CFG_PATH需为configtx.yaml所在目录
	//将生成的新组织json文件
	strcmd = fmt.Sprintf("export %s=%s && %s -printOrg %s > %s/%s.json",
	    peer_FABRIC_CFG_PATH, pathForTempData, tool_CONFIGTXGEN, infos[csshare.AddOrgOrgName], pathForTempData, infos[csshare.AddOrgOrgName])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("configtxgen -printOrg错误，stderr: %s, err: %s\n", stderr, err)
	    return fmt.Errorf("configtxgen -printOrg错误，stderr: %s, err: %s\n", stderr, err)
	}
	//4.获取通道的genesis，最新配置block，然后复制到pathForTempData，并把容器中的删除
	if tlsEnabled {
	    strcmd = fmt.Sprintf("docker exec %s peer channel fetch config /%s_config_now.block -o %s -c %s --tls --cafile %s",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgOrdererIP], infos[csshare.AddOrgChannelID], infos[csshare.AddOrgTLSCAPath])
	}else {
	    strcmd = fmt.Sprintf("docker exec %s peer channel fetch config  /%s_config_now.block -o %s -c %s",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgOrdererIP], infos[csshare.AddOrgChannelID])
	}
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行peer channel fetch config错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行peer channel fetch config错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	if tlsEnabled {
	    strcmd = fmt.Sprintf("docker exec %s peer channel fetch oldest /%s_config_genesis.block -o %s -c %s --tls --cafile %s",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgOrdererIP], infos[csshare.AddOrgChannelID], infos[csshare.AddOrgTLSCAPath])
	}else {
	    strcmd = fmt.Sprintf("docker exec %s peer channel fetch oldest /%s_config_genesis.block -o %s -c %s",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgOrdererIP], infos[csshare.AddOrgChannelID])
	}
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行peer channel fetch oldest错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行peer channel fetch oldest错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	strcmd = fmt.Sprintf("docker cp %s:/%s_config_now.block %s && docker exec %s rm -f /%s_config_now.block",
	    infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], pathForTempData, infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行docker cp now && docker exec rm -f错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行docker cp now && docker exec rm -f错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	strcmd = fmt.Sprintf("docker cp %s:/%s_config_genesis.block %s && docker exec %s rm -f /%s_config_genesis.block",
	    infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], pathForTempData, infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行docker cp genesis && docker exec rm -f错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行docker cp genesis && docker exec rm -f错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	//5.从最新的配置块中抽取通道已有的配置数据至containerid_now_config.json
	strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_config_now.block \"%s/protolator/decode/common.Block\" | %s .data.data[0].payload.data.config > %s/%s_now_config.json", pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, tool_JQ, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 5.抽取现有配置数据错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 5.抽取现有配置数据错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	//6.将新组织数据orgid.json合并至现有配置数据 - containerid_update_config.json
	strcmd = fmt.Sprintf("%s -s '.[0] * {\"channel_group\":{\"groups\":{\"Application\":{\"groups\": {\"%s\":.[1]}}}}}' %s/%s_now_config.json %s/%s.json > %s/%s_update_config.json", tool_JQ, infos[csshare.AddOrgOrgName], pathForTempData, infos[csshare.AddOrgContainerID], pathForTempData, infos[csshare.AddOrgOrgName], pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行jq - 6.合并组织配置数据至现有配置错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行jq - 6.合并组织配置数据至现有配置错误，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	//7.计算5，6两步文件的增量并转为proto格式 - containerid_update_delta.pb
	strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_now_config.json \"%s/protolator/encode/common.Config\" > %s/%s_now_config.pb",
	    pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 7.now_config.json -> now_config.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 7.now_config.json -> now_config.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_update_config.json \"%s/protolator/encode/common.Config\" > %s/%s_update_config.pb",
	    pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 7.update_config.json -> update_config.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 7.update_config.json -> update_config.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}

	strcmd = fmt.Sprintf("curl -X POST -F channel=%s -F \"original=@%s/%s_now_config.pb\" -F \"updated=@%s/%s_update_config.pb\" \"%s/configtxlator/compute/update-from-configs\" > %s/%s_update_delta.pb", infos[csshare.AddOrgChannelID], pathForTempData, infos[csshare.AddOrgContainerID], pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 7.update_config.pb - now_config.pb = delta.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 7.update_config.pb - now_config.pb = delta.pb出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	//8.将增量数据由proto转为json，然后封装到一个Envelope中
	strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_update_delta.pb \"%s/protolator/decode/common.ConfigUpdate\" | %s . > %s/%s_update_delta.json", pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, tool_JQ, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	strcmd = fmt.Sprintf("echo '{\"payload\":{\"header\":{\"channel_header\":{\"channel_id\":\"%s\", \"type\":2}},\"data\":{\"config_update\":'$(cat %s/%s_update_delta.json)'}}}' | %s . > %s/%s_update_delta_in_envelope.json", infos[csshare.AddOrgChannelID], pathForTempData, infos[csshare.AddOrgContainerID], tool_JQ, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	strcmd = fmt.Sprintf("curl -X POST --data-binary @%s/%s_update_delta_in_envelope.json \"%s/protolator/encode/common.Envelope\" > %s/%s_update_delta_in_envelope.pb", pathForTempData, infos[csshare.AddOrgContainerID], ip_CONFIGTXLATOR, pathForTempData, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]执行curl - 8.delta.pb -> delta.json出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	//9.读取整理好的升级数据，然后发给其它各个签名节点签名
	deltaSigned, err := ioutil.ReadFile(fmt.Sprintf("%s/%s_update_delta_in_envelope.pb", pathForTempData, infos[csshare.AddOrgContainerID]))
	if err != nil {
	    logger.Printf("读取%s/%s_update_delta_in_envelope.pb出错, err: %s\n", pathForTempData, infos[csshare.AddOrgContainerID], err)
	    return fmt.Errorf("读取%s/%s_update_delta_in_envelope.pb出错, err: %s\n", pathForTempData, infos[csshare.AddOrgContainerID], err)
	}

	signnodenum, err := strconv.Atoi(string(infos[csshare.AddOrgSignNodeNum]))
	if err != nil {
	    logger.Printf("strconv.Atoi(%s)出错, err: %s\n", infos[csshare.AddOrgSignNodeNum], err)
	    return fmt.Errorf("strconv.Atoi(%s)出错, err: %s\n", infos[csshare.AddOrgSignNodeNum], err)
	}
	for i := 1; i <= signnodenum; i++ {
	    signnode := strings.Split(infos[fmt.Sprintf("%s%d", csshare.AddOrgSignNode, i)], csshare.SEPARATOR)
	    if len(signnode) != 3 {
		logger.Printf("签名节点信息[%s]不符预期, err: %s\n", infos[fmt.Sprintf("signnode%d", i)], err)
		return fmt.Errorf("签名节点信息[%s]不符预期, err: %s\n", infos[fmt.Sprintf("signnode%d", i)], err)
	    }
	    data := make(map[string][]byte)
	    data["data"] = deltaSigned //供签名数据
	    data["containerid"] = []byte(signnode[1]) //容器id
	    data["customcfgpath"] = []byte(signnode[2]) //节点自定义msp路径
	    data["channelid"] = []byte(infos[csshare.AddOrgChannelID]) //通道id
	    buffer := &bytes.Buffer{}
	    err := gob.NewEncoder(buffer).Encode(data)
	    if err != nil {
		logger.Printf("gob Encode(data) failed: %s\n", err)
		continue
	    }

	    env := mecommon.GetSendEnvelope(buffer.Bytes(), mecommon.Topic_SIGN_MY_UPDATE_CONFIG)
	    if env == nil {
		logger.Println("获取发送Envelope数据失败")
		return fmt.Errorf("获取发送Envelope数据失败")
	    }
	    //最多等待3秒
	    res, err := meclient.EverythingGiveMeIsJustOK(signnode[0], env, 3*time.Second)
	    if err != nil {
		logger.Printf("签名节点[%s]-容器ID[%s]签名失败, err: %s\n", signnode[0], signnode[1], err)
		continue
	    }else {
		//将签名好的数据赋值给deltaSigned
		deltaSigned = res.Payload
	    }
	}
	//10.将签名好的升级数据写入文件
	path = fmt.Sprintf("%s/%s_update_signed_in_envelope.pb", pathForTempData, infos[csshare.AddOrgContainerID])
	if err = ioutil.WriteFile(path, deltaSigned, 0644); err != nil {
	    logger.Printf("ioutil.WriteFile deltaSigned[%s] error: %s\n", path, err)
	    return fmt.Errorf("ioutil.WriteFile deltaSigned[%s] error: %s\n", path, err)
	}
	//11.将签名好的文件复制到容器的根目录，并升级，然后将有用的文件转移到save目录
	strcmd = fmt.Sprintf("docker cp %s %s:/", path, infos[csshare.AddOrgContainerID])
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]docker cp出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	    return fmt.Errorf("节点容器[%s]docker cp出错，stderr: %s, err: %s\n", infos[csshare.AddOrgContainerID], stderr, err)
	}
	if tlsEnabled {
	    strcmd = fmt.Sprintf("docker exec %s peer channel update -f /%s_update_signed_in_envelope.pb -c %s -o %s --tls --cafile %s 2>&1",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgChannelID], infos[csshare.AddOrgOrdererIP], infos[csshare.AddOrgTLSCAPath])
	}else {
	    strcmd = fmt.Sprintf("docker exec %s peer channel update -f /%s_update_signed_in_envelope.pb -c %s -o %s 2>&1",
		infos[csshare.AddOrgContainerID], infos[csshare.AddOrgContainerID], infos[csshare.AddOrgChannelID], infos[csshare.AddOrgOrdererIP])
	}
	stdout, _, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]docker exec peer channel update出错，stdout: %s, err: %s\n", infos[csshare.AddOrgContainerID], stdout, err)
	    return fmt.Errorf("节点容器[%s]docker exec peer channel update出错，stdout: %s, err: %s\n", infos[csshare.AddOrgContainerID], stdout, err)
	}else {
	    //"Global Flags:"是cobra命令执行的函数若返回错误，默认会打印用法，"Global Flags:"是打印出来的内容
	    if strings.Index(stdout, "Usage:") >= 0 && strings.Index(stdout, "Flags:") >= 0 {
		logger.Printf("节点容器[%s]docker exec peer channel update失败，stdout: %s, err: %s\n", infos[csshare.AddOrgContainerID], stdout, err)
		return fmt.Errorf("节点容器[%s]docker exec peer channel update失败，stdout: %s, err: %s\n", infos[csshare.AddOrgContainerID], stdout, err)
	    }

	    logger.Printf("节点容器[%s]-新组织[%s]配置数据加入[%s]成功\n", infos[csshare.AddOrgContainerID], infos[csshare.AddOrgOrgName], infos[csshare.AddOrgChannelID])
	}
	//将有用的文件复制到save目录 - crypto-config %s_update_delta_in_envelope.json
	stdout = time.Now().Format("20060102150405")
	strcmd = fmt.Sprintf("cd %s && mv crypto-config %s/crypto-config-%s && mv %s_update_delta_in_envelope.json %s/%s_update_delta_in_envelope_%s.json ",
	    pathForTempData, pathForTempSave, stdout, infos[csshare.AddOrgContainerID], pathForTempSave, infos[csshare.AddOrgContainerID], stdout)
	_, stderr, err = doCommand("bash", "-c", strcmd)
	if err != nil {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("移动文件crypto-config到save目录失败，stderr: %s, err: %s\n", stderr, err)
	}
    }else if metadata.FabricVersion == "1.1" {

    }else {
	logger.Println("不支持的fabric版本")
	return fmt.Errorf("不支持的fabric版本")
    }

    //清理工作
    err = killConfigtxlator(configtxlator)
    if err != nil {
	logger.Printf("停止configtxlator进程失败, err: %s\n", err)
    }

    return nil
}

/*
//data是addOrgDataToChannelConfig中发送而来的用于签名的更新增量数据和信息
data["data"] = deltaSigned //供签名数据
data["containerid"] = []byte(signnode[1]) //容器id
data["customcfgpath"] = []byte(signnode[2]) //节点自定义msp路径
data["channelid"] = []byte(infos[csshare.AddOrgChannelID]) //通道id
*/
func signUpdateConfig(data []byte) []byte {
    var stdout, stderr, strcmd string
    var err error
    dataAndInfo := make(map[string][]byte)
    buffer := bytes.NewBuffer(data)
    err = gob.NewDecoder(buffer).Decode(&dataAndInfo)
    if err != nil {
	logger.Printf("gob Decode失败: %s\n", err)
	return nil
    }

    containerID := string(dataAndInfo["containerid"])
    channelID := string(dataAndInfo["channelid"])
    //1.确定配置所在路径
    fabric_cfg_path := strings.TrimRight(string(dataAndInfo["customcfgpath"]), "/")
    if fabric_cfg_path == "" {
	//若客户端未指定FABRIC_CFG_PATH路径，则默认获取容器中的FABRIC_CFG_PATH环境值
	//默认节点的MSP与core.yaml均在此目录下
	//TODO:peer的FABRIC_CFG_PATH所在目录默认有三个，可以增加如果从peer_FABRIC_CFG_PATH下无法获取，则尝试
	//从另外两个目录获取
	strcmd = fmt.Sprintf("(docker exec %s env) | grep '%s=' | awk -F= '{print $2}'", containerID, peer_FABRIC_CFG_PATH)
	stdout, stderr, err = doCommand("bash", "-c", strcmd)
	stdout = strings.TrimRight(stdout, "\n")
	if err != nil || stdout == "" {
	    logger.Println("strcmd: ", strcmd)
	    logger.Printf("节点容器[%s]获取FABRIC_CFG_PATH环境变量值出错，stderr: %s, err: %s\n", containerID, stderr, err)
	    return nil
	}

	fabric_cfg_path = stdout
    }
    if containerID == "" || channelID == "" || fabric_cfg_path == "" || dataAndInfo["data"] == nil {
	logger.Println("提供的签名数据不符预期")
	return nil
    }

    //2.将签名节点的msp，core.yaml从配置路径中复制出来
    strcmd = fmt.Sprintf("docker cp %s:%s/msp %s", containerID, fabric_cfg_path, pathForTempData)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("节点容器[%s]执行docker cp msp出错，stderr: %s, err: %s\n", containerID, stderr, err)
	return nil
    }

    strcmd = fmt.Sprintf("docker cp %s:%s/core.yaml %s", containerID, fabric_cfg_path, pathForTempData)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("节点容器[%s]执行docker cp core.yaml出错，stderr: %s, err: %s\n", containerID, stderr, err)
	return nil
    }
    strcmd = fmt.Sprintf("docker cp %s:%s/tls %s", containerID, fabric_cfg_path, pathForTempData)
    _, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("节点容器[%s]执行docker cp tls出错，stderr: %s, err: %s\n", containerID, stderr, err)
	return nil
    }
    //3.取出CORE_PEER_LOCALMSPID值
    strcmd = fmt.Sprintf("docker exec %s env | grep CORE_PEER_LOCALMSPID | awk -F= '{print $2}'", containerID)
    stdout, stderr, err = doCommand("bash", "-c", strcmd)
    if err != nil {
	logger.Println("strcmd: ", strcmd)
	logger.Printf("节点容器[%s]执行docker cp msp出错，stderr: %s, err: %s\n", containerID, stderr, err)
	return nil
    }
    localMspID := strings.TrimRight(stdout, "\n")
    //4.设置一些环境变量以供伪装使用
    //这些变量有些或可不设置，不清楚具体影响，姑且设置
    //设置本地MSP路径
    fabric_cfg_path = fmt.Sprintf("%s/%s", pathForTempData, peer_mspConfigPath)
    err = os.Setenv("CORE_PEER_LOCALMSPID", localMspID)
    if err != nil {
	logger.Println("CORE_PEER_LOCALMSPID设置失败")
	return nil
    }
    err = os.Setenv("FABRIC_CFG_PATH", pathForTempData)
    if err != nil {
	logger.Println("FABRIC_CFG_PATH设置失败")
	return nil
    }
    err = os.Setenv("CORE_PEER_MSPCONFIGPATH", fabric_cfg_path)
    if err != nil {
	logger.Println("CORE_PEER_MSPCONFIGPATH设置失败")
	return nil
    }
    //5.初始化本地msp
    logger.Printf("模拟初始化本地MSP[fabric_cfg_path:%s, localMspID:%s]\n", fabric_cfg_path, localMspID)
    err = fpeercommon.InitCrypto(fabric_cfg_path, localMspID)
    if err != nil {
	logger.Printf("初始化本地MSP失败[fabric_cfg_path:%s, localMspID:%s], err: %s\n", fabric_cfg_path, localMspID, err)
	return nil
    }
    //6.一系列检查，偷取于peer/channel/create.go中的sanityCheckAndSignConfigTx函数
    chUptEnv, err := fprotosutils.UnmarshalEnvelope(dataAndInfo["data"])
    if err != nil {
	logger.Printf("Unmarshal数据失败, err: %s\n", err)
	return nil
    }
    payload, err := fprotosutils.ExtractPayload(chUptEnv)
    if err != nil {
	logger.Printf("ExtractPayload error, err: %s\n", err)
	return nil
    }
    if payload.Header == nil || payload.Header.ChannelHeader == nil {
	logger.Println("payload.Header == nil || payload.Header.ChannelHeader == nil，不符预期")
	return nil
    }
    ch, err := fprotosutils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
    if err != nil {
	logger.Printf("UnmarshalChannelHeader error, err: %s\n", err)
	return nil
    }
    if ch.Type != int32(fprotoscommon.HeaderType_CONFIG_UPDATE) {
	logger.Println("ch.Type != int32(fprotoscommon.HeaderType_CONFIG_UPDATE) error，不符预期")
	return nil
    }
    if ch.ChannelId == "" {
	logger.Println("ch.ChannelId == \"\" error，不符预期")
	return nil
    }
    if ch.ChannelId != channelID {
	logger.Println("ch.ChannelId != channelID error，不符预期")
	return nil
    }
    configUpdateEnv, err := fcommonconfigtx.UnmarshalConfigUpdateEnvelope(payload.Data)
    if err != nil {
	logger.Printf("UnmarshalConfigUpdateEnvelope error, err: %s\n", err)
	return nil
    }
    //7.创建"签名笔"，签名数据
    signer := flocalsigner.NewSigner()
    sigHeader, err := signer.NewSignatureHeader()
    if err != nil {
	logger.Printf("创建签名头失败，err: %s\n", err)
	return nil
    }
    configSig := &fprotoscommon.ConfigSignature{
	SignatureHeader: fprotosutils.MarshalOrPanic(sigHeader),
    }

    configSig.Signature, err = signer.Sign(fcommonutil.ConcatenateBytes(configSig.SignatureHeader, configUpdateEnv.ConfigUpdate))
    configUpdateEnv.Signatures = append(configUpdateEnv.Signatures, configSig)
    signedEnv, err := fprotosutils.CreateSignedEnvelope(fprotoscommon.HeaderType_CONFIG_UPDATE, channelID, signer, configUpdateEnv, 0, 0)
    if err != nil {
	logger.Printf("创建签名Envelope失败，err: %s\n", err)
	return nil
    }

    fake_aha, err := proto.Marshal(signedEnv)
    if err != nil {
	logger.Println("proto.Marshal(signedEnv)失败，err: %s\n", err)
	return nil
    }

    //8.清理
    err = os.Unsetenv("CORE_PEER_LOCALMSPID")
    if err != nil {
	logger.Println("CORE_PEER_LOCALMSPID设置失败")
    }
    err = os.Unsetenv("FABRIC_CFG_PATH")
    if err != nil {
	logger.Println("FABRIC_CFG_PATH设置失败")
    }
    err = os.Unsetenv("CORE_PEER_MSPCONFIGPATH")
    if err != nil {
	logger.Println("CORE_PEER_MSPCONFIGPATH设置失败")
    }

    logger.Printf("容器[%s]签名成功\n", containerID)
    return fake_aha
}

//清空工作 - 清空dir目录下的del文件
func clearJob(dir string, save []string) {
    if dir == "" || len(save) == 0 {
	logger.Println("dir or save is nil")
	return
    }
    var savefiles string
    for _, file := range save {
	savefiles += (file + ":")
    }
    savefiles = savefiles[:len(savefiles) - 1]
    strcmd := fmt.Sprintf("export GLOBIGNORE=%s && cd %s && rm -rf -v *", savefiles, dir)
    _, stderr, err := doCommand("bash", "-c", strcmd)

    if err != nil {
	logger.Println("strcmd:", strcmd)
	logger.Printf("清空目录[%s]失败, stderr: %s\n", dir, stderr)
    }
}
