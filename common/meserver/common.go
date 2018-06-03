

package main



import (

)

type DEALSTATE int

const (
    DoNothing                          DEALSTATE = DEALSTATE(0x00)
    //获取当前容器信息
    GettedCurrentContainerInfo         DEALSTATE = DEALSTATE(0x01)
    //新配置文件.yaml
    WrittedConfigDataToFile            DEALSTATE = DEALSTATE(0x02)
    CopiedConfigFileToCurrentContainer DEALSTATE = DEALSTATE(0x04)
    CommittedCurrentContainer          DEALSTATE = DEALSTATE(0x08)
    DeleteCurrentContainer             DEALSTATE = DEALSTATE(0x10)
    //docker-compose-file
    UpdatedContainerInfo               DEALSTATE = DEALSTATE(0x11)
    WrittedDockerComposeFile           DEALSTATE = DEALSTATE(0x12)
    RanNewContainer                    DEALSTATE = DEALSTATE(0x14) // 只要此状态，就算更新成功
    CleanedTempData                    DEALSTATE = DEALSTATE(0x18)
    AllDone                            DEALSTATE = DEALSTATE(0x20)
)

//在meserver.go的init中初始化
var STEPS_EXPLAIN map[DEALSTATE]string

//deal_state - 针对容器部署
//0 - 结构信息未初始化
//1 - 成功获取原始容器信息
//2 - 成功将新配置数据写入配置文件,（并检查了各个字段的有效性，这里检查的是和服务端信息有关的字段，如端口是否被占用等）
//3 - 成功根据新配置数据更新了容器信息
//4 - 成功将配置文件复制入现有容器
//5，6 - 成功将现有容器commit，获取新的imageID，并删除现有容器
//7 - 成功将容器信息写入docker-compose文件
//8，9 - 成功启动新的容器，（并清理临时文件）

//成员后有.xxx的，均为执行docker inspect --format=... containerID从现有容器获取的信息赋值
type containerInfo struct {
    service string //.Config.Labels.com.docker.compose.service
    id string //.Id
    name string //.Name
    imageID string //.Image
    imageName string //.Config.Image
    //将现有容器docker commit之后得到的新的镜像ID
    //由dockerCommitAndStopAndDelteCurrentContainer记录
    //若新建不成功，则为空
    imageIDForDockerCommit string
    configPath string //有效配置路径之一
    //orderer读取配置的时候会读取全部的以ORDERER为开头的配置，Peer则以CORE_PEER开头
    //所以这里存储所有从容器中查出的以ORDERER开头的环境变量
    //这个ORDERER是源码orderer/localconfig/config.go中的Prefix定义的
    environments []string //单独使用docker exect ... env获取
    working_dir string //.Config.WorkingDir
    command string //.Config.Cmd
    volumes []string//.HostConfig.Binds
    ports []string //.NetworkSettings.Ports
    networks []string //.NetworkSettings.Networks
    networkMode string //.HostConfig.NetworkMode
    startedAt string //.State.StartedAt
    //changes []string //变动的文件路径，由docker diff获取

    dealState DEALSTATE
}

//在getPeerBasicInfo()时使用，用于搜索peer容器节点是否开启TLS的环境变量的key
var CORE_PEER_TLS_ENABLED_ENV_KEY string = "CORE_PEER_TLS_ENABLED"
