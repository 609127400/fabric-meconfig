
package main


import (
    "fmt"
    "testing"
    "strings"
    "github.com/stretchr/testify/assert"
    "github.com/fabric-meconfig/common/csshare"
)


func TestGetContainerIDs(t *testing.T) {
    var stdout string = `
59da814152d4        hyperledger/fabric-peer                                                                                "peer node start"        7 hours ago         Up 7 hours          0.0.0.0:8051->7051/tcp, 0.0.0.0:8053->7053/tcp     peer1.org1.example.com
0143be87785d        hyperledger/fabric-peer                                                                                "peer node start"        7 hours ago         Up 7 hours          0.0.0.0:7051->7051/tcp, 0.0.0.0:7053->7053/tcp     peer0.org1.example.com
29a950643f89        hyperledger/fabric-peer                                                                                "peer node start"        7 hours ago         Up 7 hours          0.0.0.0:10051->7051/tcp, 0.0.0.0:10053->7053/tcp   peer1.org2.example.com
a537ffd99b9d        hyperledger/fabric-peer                                                                                "peer node start"        7 hours ago         Up 7 hours          0.0.0.0:9051->7051/tcp, 0.0.0.0:9053->7053/tcp     peer0.org2.example.com
`
    containers_info := strings.Split(stdout, "\n")
    containers_num := len(containers_info) - 1 //用\n分割信息，最后一个是空
    containerIDs := make([]string, containers_num)
    for i := 0; i < containers_num; i++ {
	//从每个containers_info中截取容器ID（从0开始到遇到的第一个空格的位置）
	containerIDs[i] = containers_info[i][:strings.Index(containers_info[i]," ")]
    }
    assert.Equal(t, len(containerIDs), 4)
    assert.Equal(t, containerIDs[0], "59da814152d4")
    assert.Equal(t, containerIDs[1], "0143be87785d")
    assert.Equal(t, containerIDs[2], "29a950643f89")
    assert.Equal(t, containerIDs[3], "a537ffd99b9d")
}

func TestGetContainerInfo1(t *testing.T) {
    /*
    sourceOutput1 := "/peer1.org1.example.com|bb7e6ded48c0c24c856e92771add2a7cdc388469a898ca7960e4f2f151397c51|sha256:1ce935adc397705eb9169e98a8316fc69e6ac7a64fa1b9ea78326e534216b5e2|/opt/gopath/src/github.com/hyperledger/fabric/peer|[peer node start]|[/var/run:/host/var/run:rw /home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp:/etc/hyperledger/fabric/msp:rw /home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls:/etc/hyperledger/fabric/tls:rw]|map[7051/tcp:[map[HostIp:0.0.0.0 HostPort:8051]] 7053/tcp:[map[HostIp:0.0.0.0 HostPort:8053]]]|net_byfn|"

    sourceOutput2 := "/peer0.org3.otcclear.com|a17aec6d17a2e7365af9906367acb66097188807e3686e11f09cad224dfce845|sha256:8015e9901dd30a75f2d34a71e51bdcfcbf3ce60c646207c7ffce698908d2f508|/opt/gopath/src/github.com/hyperledger/fabric/peer|[/bin/bash -c peer node start > peerlog.txt 2>&1 ]|[/var/run:/host/var/run:rw /opt/e2e_cli/fabricconfig/datapublickeypath/peer2:/etc/hyperledger/datapublickeypath:rw /opt/e2e_cli/fabricconfig/crypto/peerOrganizations/org3.otcclear.com/peers/peer0.org3.otcclear.com/msp:/etc/hyperledger/fabric/msp:rw /opt/e2e_cli/fabricconfig/crypto/peerOrganizations/org3.otcclear.com/peers/peer0.org3.otcclear.com/tls:/etc/hyperledger/fabric/tls:rw /opt/e2e_cli/fabricconfig/dataprivatekeypath/peer2:/etc/hyperledger/dataprivatekeypath:rw]|map[7051/tcp:[map[HostIp:0.0.0.0 HostPort:9051]] 7052/tcp:[map[HostIp:0.0.0.0 HostPort:9052]] 7053/tcp:[map[HostIp:0.0.0.0 HostPort:9053]]]|e2ecli_default|"
    */
    example1 := &containerInfo{}
    //container2 := &containerInfo{}

    example1.name = "peer1.org1.example.com"
    example1.id = "bb7e6ded48c0c24c856e92771add2a7cdc388469a898ca7960e4f2f151397c51"
    example1.imageID = "1ce935adc397705eb9169e98a8316fc69e6ac7a64fa1b9ea78326e534216b5e2"
    example1.configPath = "/etc/hyperledger/fabric"
    example1.environments = make([]string, 15)
	example1.environments[0] = "CORE_PEER_ID=peer1.org1.example.com"
	example1.environments[1] = "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt"
	example1.environments[2] = "CORE_PEER_GOSSIP_USELEADERELECTION=true"
	example1.environments[3] = "CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt"
	example1.environments[4] = "CORE_PEER_PROFILE_ENABLED=true"
	example1.environments[5] = "CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=net_byfn"
	example1.environments[6] = "CORE_PEER_TLS_ENABLED=true"
	example1.environments[7] = "CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer1.org1.example.com:7051"
	example1.environments[8] = "CORE_LOGGING_LEVEL=DEBUG"
	example1.environments[9] = "CORE_PEER_LOCALMSPID=Org1MSP"
	example1.environments[10] = "CORE_PEER_ADDRESS=peer1.org1.example.com:7051"
	example1.environments[11] = "CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org1.example.com:7051"
	example1.environments[12] = "CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock"
	example1.environments[13] = "CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key"
	example1.environments[14] = "CORE_PEER_GOSSIP_ORGLEADER=false"
    example1.working_dir = "/opt/gopath/src/github.com/hyperledger/fabric/peer"
    example1.command = "peer node start"
    example1.volumes = make([]string, 3)
	example1.volumes[0] = "/var/run:/host/var/run"
	example1.volumes[1] = "/home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp:/etc/hyperledger/fabric/msp"
	example1.volumes[2] = "/home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls:/etc/hyperledger/fabric/tls"
    example1.ports = make([]string, 2)
	example1.ports[0] = "8051:7051"
	example1.ports[1] = "8053:7053"
    example1.networks = "byfn"

    containers := getContainersInfo ("CORE_PEER", "peer", "", "grep", "chaincode")

    assert.Equal(t, len(containers), 4)
    assert.Equal(t, containers[3].name, example1.name)
    assert.Equal(t, containers[3].id, example1.id)
    assert.Equal(t, containers[3].imageID, example1.imageID)
    assert.Equal(t, containers[3].configPath, example1.configPath)
    assert.Equal(t, containers[3].environments[0],example1.environments[0])
    assert.Equal(t, containers[3].environments[1],example1.environments[1])
    assert.Equal(t, containers[3].environments[2],example1.environments[2])
    assert.Equal(t, containers[3].environments[3],example1.environments[3])
    assert.Equal(t, containers[3].environments[4],example1.environments[4])
    assert.Equal(t, containers[3].environments[5],example1.environments[5])
    assert.Equal(t, containers[3].environments[6],example1.environments[6])
    assert.Equal(t, containers[3].environments[7],example1.environments[7])
    assert.Equal(t, containers[3].environments[8],example1.environments[8])
    assert.Equal(t, containers[3].environments[9],example1.environments[9])
    assert.Equal(t, containers[3].environments[10],example1.environments[10])
    assert.Equal(t, containers[3].environments[11],example1.environments[11])
    assert.Equal(t, containers[3].environments[12],example1.environments[12])
    assert.Equal(t, containers[3].environments[13],example1.environments[13])
    assert.Equal(t, containers[3].environments[14],example1.environments[14])
    assert.Equal(t, containers[3].working_dir, example1.working_dir)
    assert.Equal(t, containers[3].command, example1.command)
    assert.Equal(t, containers[3].volumes[0],example1.volumes[0])
    assert.Equal(t, containers[3].volumes[1],example1.volumes[1])
    assert.Equal(t, containers[3].volumes[2],example1.volumes[2])
    assert.Equal(t, containers[3].ports[0],example1.ports[0])
    assert.Equal(t, containers[3].ports[1],example1.ports[1])
    assert.Equal(t, containers[3].networks, example1.networks)
}

func TestGetContainerInfo2(t *testing.T) {
    sourceOutput1 := "2018-04-30T14:51:06.887337509Z|23d331ad120fda074f9fec8424c60f93d0657860e56003b81c4a7bdf448e0e03|/peer1.org1.example.com|sha256:1ce935adc397705eb9169e98a8316fc69e6ac7a64fa1b9ea78326e534216b5e2|/opt/gopath/src/github.com/hyperledger/fabric/peer|[peer node start]|[/var/run:/host/var/run:rw /home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp:/etc/hyperledger/fabric/msp:rw /home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls:/etc/hyperledger/fabric/tls:rw]|8051:7051/tcp+8053:7053/tcp+|net_byfn|map[com.docker.compose.oneoff:False com.docker.compose.project:net com.docker.compose.service:peer1.org1.example.com com.docker.compose.version:1.13.0 org.hyperledger.fabric.base.version:0.3.2 org.hyperledger.fabric.version:1.0.4 com.docker.compose.config-hash:6d5895306f65b05c015ed70379b0819d96681ce6dc7925e67673d7d3cbc5a745 com.docker.compose.container-number:1]|hyperledger/fabric-peer|"

    infos := strings.Split(sourceOutput1,"|")
    assert.Equal(t, len(infos), 12)

    ci := &containerInfo{}
    //startedat
    ci.startedat = infos[0][:strings.Index(infos[0], ".")]
    assert.Equal(t, ci.startedat, "2018-04-30T14:51:06")
    //ID
    ci.id = infos[1]
    assert.Equal(t, ci.id, "23d331ad120fda074f9fec8424c60f93d0657860e56003b81c4a7bdf448e0e03")
    //Name
    ci.name = infos[2][1:]
    assert.Equal(t, ci.name, "peer1.org1.example.com")
    //Image
    imageid := strings.Split(infos[3], ":")
    assert.Equal(t, len(imageid), 2)
    ci.imageID = imageid[1]
    assert.Equal(t, ci.imageID, "1ce935adc397705eb9169e98a8316fc69e6ac7a64fa1b9ea78326e534216b5e2")
    //configPath，与具体情况相关
    ci.configPath = getOneValidOrdererConfigPath(ci.id)
    assert.Equal(t, ci.configPath, "/etc/hyperledger/fabric")
    //environments，与具体情况有关
    strcmd := fmt.Sprintf("docker exec %s env | grep %s", ci.id, "CORE")
    stdout, stderr, err := doCommand("bash", "-c", strcmd)
    assert.Nil(t, err, stderr)
    envPairs := strings.Split(stdout, "\n")
    envNum := len(envPairs) - 1 //最后一行的\n若Splic后会多出来一个空的
    assert.Equal(t, envNum, 15)
    ci.environments = make([]string, envNum)
    for i := 0; i < envNum; i++ {
	ci.environments[i] = envPairs[i]
    }
    assert.Equal(t, ci.environments[0], "CORE_PEER_ID=peer1.org1.example.com")
    assert.Equal(t, ci.environments[1], "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt")
    assert.Equal(t, ci.environments[2], "CORE_PEER_GOSSIP_USELEADERELECTION=true")
    //working_dir
    ci.working_dir = infos[4]
    assert.Equal(t, ci.working_dir, "/opt/gopath/src/github.com/hyperledger/fabric/peer")
    //command
    infos[5] = infos[5][1:(len(infos[5]) - 1)]
    ci.command = infos[5]
    assert.Equal(t, ci.command, "peer node start")
    //volumes
    infos[6] = infos[6][1:(len(infos[6]) - 1)]
    vols := strings.Split(infos[6], " ")
    volNum := len(vols)
    assert.Equal(t, volNum, 3)
    ci.volumes = make([]string, volNum)
    for i := 0; i < volNum; i++ {
	//去除最后一个:后的rw
	ci.volumes[i] = vols[i][:strings.LastIndex(vols[i], ":")]
    }
    assert.Equal(t, ci.volumes[0], "/var/run:/host/var/run")
    assert.Equal(t, ci.volumes[1], "/home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp:/etc/hyperledger/fabric/msp")
    assert.Equal(t, ci.volumes[2], "/home/wyz/fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls:/etc/hyperledger/fabric/tls")
    //ports 8051:7051/tcp+8053:7053/tcp+
    ports := strings.Split(infos[7], "+")
    portNum := len(ports) - 1
    assert.Equal(t, portNum, 2)
    ci.ports = make([]string, portNum)
    for i := 0; i < portNum; i++ {
	// 7051/tcp:[{0.0.0.0 8051}]
	diagonal_pos := strings.Index(ports[i], "/")
	ci.ports[i] = ports[i][:diagonal_pos]
    }
    assert.Equal(t, ci.ports[0], "8051:7051")
    assert.Equal(t, ci.ports[1], "8053:7053")
    //networks net_byfn
    nets := strings.Split(infos[8], "_")
    assert.Equal(t, len(nets), 2)
    ci.networks = nets[1]
    assert.Equal(t, ci.networks, "byfn")
    //service
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
    assert.Equal(t, ci.service, "peer1.org1.example.com")
    //imageName
    ci.imageName = infos[10]
    assert.Equal(t, ci.imageName, "hyperledger/fabric-peer")


    fmt.Println("")

    fmt.Printf("节点容器[%s]信息:\n", ci.id)
    fmt.Printf("信息项\t值\t\n")
    fmt.Printf("启动时间\t%s\t\n", ci.startedat)
    fmt.Printf("容器ID\t%s\t\n", ci.id)
    fmt.Printf("名称\t%s\t\n", ci.name)
    fmt.Printf("镜像ID\t%s\t\n", ci.imageID)
    fmt.Printf("镜像名称\t%s\t\n", ci.imageName)
    fmt.Printf("配置路径\t%s\t\n", ci.configPath)
    fmt.Printf("环境变量:\t\t\n")
	for i := 0; i < envNum; i++ {
	    fmt.Printf("    %s\t\t\n", ci.environments[i])
	}
    fmt.Printf("工作目录\t%s\t\n", ci.working_dir)
    fmt.Printf("启动命令\t%s\t\n", ci.command)
    fmt.Printf("数据卷:\t\t\n")
	for i := 0; i < volNum; i++ {
	    fmt.Printf("    %s\t\t\n", ci.volumes[i])
	}
    fmt.Printf("映射端口\t\t\n")
	for i := 0; i < portNum; i++ {
	    fmt.Printf("    %s\t\t\n", ci.ports[i])
	}
    fmt.Printf("网络名称\t%s\t\n", ci.networks)
    fmt.Printf("服务名称\t%s\t\n", ci.service)

    fmt.Println("")
}

func TestGetPeerChannelDetailInfo(t *testing.T) {
    PolicyStr := `
{
  "type": 3,
  "value": {
    "rule": "MAJORITY",
    "sub_policy": "Admins"
  }
}
`
    pv := &csshare.Policy{}
    err = json.Unmarshal([]byte(PolicyStr), pv)
    assert.Equal(t, err, nil)
    assert.Equal(t, pv.Value.Rule, "MAJORITY")

    CVStr := `
{
  "mod_policy": "Admins",
  "value": {
    "config": {
      "admins": [
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWIrZ0F3SUJBZ0lRVS93QUNEb1BuUExVUlJJVEpHNVE0REFLQmdncWhrak9QUVFEQWpCek1Rc3cKQ1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ4TU5VMkZ1SUVaeQpZVzVqYVhOamJ6RVpNQmNHQTFVRUNoTVFiM0puTVM1bGVHRnRjR3hsTG1OdmJURWNNQm9HQTFVRUF4TVRZMkV1CmIzSm5NUzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhPREExTVRVeE5qVTNNRGhhRncweU9EQTFNVEl4TmpVM01EaGEKTUZzeEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVApZVzRnUm5KaGJtTnBjMk52TVI4d0hRWURWUVFEREJaQlpHMXBia0J2Y21jeExtVjRZVzF3YkdVdVkyOXRNRmt3CkV3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSVdZQllTK1lydmsvOFdUWk53UXdmU3QvUE1uZ29LM04Kd3d3OUxQNkFBc2ozbkwxb0FTZjd1aFlqR2RIT2NjclNjcFgrK1VDMENHOHpncS9KRi9BempLTk5NRXN3RGdZRApWUjBQQVFIL0JBUURBZ2VBTUF3R0ExVWRFd0VCL3dRQ01BQXdLd1lEVlIwakJDUXdJb0FnTGw0M1c3QWVZK3dLClNmYU1ySlZHZ3crR0MvZU9PNHBjOWFWNnBBZWo2djB3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnQVR6TU10ejgKR1BJalZ1b1U2YVNGZ0JGRXVHWlpodWFXNGZNWllqcE1FNllDSUREbmFFVDAyalAreG1uNWpsU2pJYnpvTE00eQoyUWFLWDBjeTFSbk80d0wxCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
      ],
      "crypto_config": {
        "identity_identifier_hash_function": "SHA256",
        "signature_hash_family": "SHA2"
      },
      "name": "Org1MSP",
      "root_certs": [
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNRekNDQWVtZ0F3SUJBZ0lRSVpNcWZ2a3FWTG51MEEyVTdFYzV5REFLQmdncWhrak9QUVFEQWpCek1Rc3cKQ1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ4TU5VMkZ1SUVaeQpZVzVqYVhOamJ6RVpNQmNHQTFVRUNoTVFiM0puTVM1bGVHRnRjR3hsTG1OdmJURWNNQm9HQTFVRUF4TVRZMkV1CmIzSm5NUzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhPREExTVRVeE5qVTNNRGRhRncweU9EQTFNVEl4TmpVM01EZGEKTUhNeEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVApZVzRnUm5KaGJtTnBjMk52TVJrd0Z3WURWUVFLRXhCdmNtY3hMbVY0WVcxd2JHVXVZMjl0TVJ3d0dnWURWUVFECkV4TmpZUzV2Y21jeExtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUKMGxVYmVJZm95RDRpdWNCcFFvV0MxUTVVR1grY0hqVUV0b25SZHRhT2ZsZk9Nd2lBSlJkalBMYVFHV1hWeVM2NgpWbHBQVVVoZmhYNk1za1orV0I3bG1LTmZNRjB3RGdZRFZSMFBBUUgvQkFRREFnR21NQThHQTFVZEpRUUlNQVlHCkJGVWRKUUF3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFwQmdOVkhRNEVJZ1FnTGw0M1c3QWVZK3dLU2ZhTXJKVkcKZ3crR0MvZU9PNHBjOWFWNnBBZWo2djB3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUk1RFhleElON3B2bFQzRwpQcnIwby9rVnk5WUNlb1NtSStCV2t1UHBrV3FXQWlCRlplMkQyWmFBT1NjSTlBdWZJN1JzaFJsQ29Xc0RuSEhECmI1TDRBTWRNT1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
      ],
      "tls_root_certs": [
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNTakNDQWZDZ0F3SUJBZ0lSQUozRUVueU15dGxaZnF6NnJPbXNjTDR3Q2dZSUtvWkl6ajBFQXdJd2RqRUwKTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY1REVk5oYmlCRwpjbUZ1WTJselkyOHhHVEFYQmdOVkJBb1RFRzl5WnpFdVpYaGhiWEJzWlM1amIyMHhIekFkQmdOVkJBTVRGblJzCmMyTmhMbTl5WnpFdVpYaGhiWEJzWlM1amIyMHdIaGNOTVRnd05URTFNVFkxTnpBM1doY05Namd3TlRFeU1UWTEKTnpBM1dqQjJNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRQpCeE1OVTJGdUlFWnlZVzVqYVhOamJ6RVpNQmNHQTFVRUNoTVFiM0puTVM1bGVHRnRjR3hsTG1OdmJURWZNQjBHCkExVUVBeE1XZEd4elkyRXViM0puTVM1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDkKQXdFSEEwSUFCSmhNN1JEWUF4d0NTbHFza1I2RDZxbGRyeHpoeUVSMWZZMXU4K0lqTTZQUjRRTFB5VU0xb1Z2Kwo1Uk54Q0laOVE2UG00Q0g0VElMTFcyWXBBM0JCeTEralh6QmRNQTRHQTFVZER3RUIvd1FFQXdJQnBqQVBCZ05WCkhTVUVDREFHQmdSVkhTVUFNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdLUVlEVlIwT0JDSUVJQ0ovRjFoNDBwcWcKbzRadjRjbU9qTmQvbTdjaGxCSXI4UzZreU4ybzNpSWtNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUURGKzlxMAo2U3pRL3A4K2oyOGpFdkE5UUpTemxIbGJzVi9GZURHU0tueENLQUlnVFFjZEpjMG5iQ2FFbC9tdmxaR1ZYVFczCjhNWEZZNzBHOW4vZHhvRjZWcXM9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
      ]
    },
    "type": 0
  },
  "version": "0"
}
`
    var cv csshare.ConfigValue
    cv.Value = &csshare.MSPConfig{}
    err = json.Unmarshal([]byte(PolicyStr), &cv)
    assert.Equal(t, err, nil)
    assert.Equal(t, cv.Value.(*csshare.MSPConfig).Config.Admins[0], `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWIrZ0F3SUJBZ0lRVS93QUNEb1BuUExVUlJJVEpHNVE0REFLQmdncWhrak9QUVFEQWpCek1Rc3cKQ1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ4TU5VMkZ1SUVaeQpZVzVqYVhOamJ6RVpNQmNHQTFVRUNoTVFiM0puTVM1bGVHRnRjR3hsTG1OdmJURWNNQm9HQTFVRUF4TVRZMkV1CmIzSm5NUzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhPREExTVRVeE5qVTNNRGhhRncweU9EQTFNVEl4TmpVM01EaGEKTUZzeEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVApZVzRnUm5KaGJtTnBjMk52TVI4d0hRWURWUVFEREJaQlpHMXBia0J2Y21jeExtVjRZVzF3YkdVdVkyOXRNRmt3CkV3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSVdZQllTK1lydmsvOFdUWk53UXdmU3QvUE1uZ29LM04Kd3d3OUxQNkFBc2ozbkwxb0FTZjd1aFlqR2RIT2NjclNjcFgrK1VDMENHOHpncS9KRi9BempLTk5NRXN3RGdZRApWUjBQQVFIL0JBUURBZ2VBTUF3R0ExVWRFd0VCL3dRQ01BQXdLd1lEVlIwakJDUXdJb0FnTGw0M1c3QWVZK3dLClNmYU1ySlZHZ3crR0MvZU9PNHBjOWFWNnBBZWo2djB3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnQVR6TU10ejgKR1BJalZ1b1U2YVNGZ0JGRXVHWlpodWFXNGZNWllqcE1FNllDSUREbmFFVDAyalAreG1uNWpsU2pJYnpvTE00eQoyUWFLWDBjeTFSbk80d0wxCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`)

}
