
package main

import(
	"fmt"
	"strings"
	"os"
	"io/ioutil"
	"encoding/json"
	"path/filepath"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"encoding/hex"
	"hash"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/golang/protobuf/proto"

	//fconfig "github.com/hyperledger/fabric/common/channelconfig"//1.2
	fconfig "github.com/hyperledger/fabric/common/config"//1.0
	fprotoutils "github.com/hyperledger/fabric/protos/utils"
	fbccsputils "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/util"
	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
	mb "github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/common/tools/configtxlator/update"
	fcrypto "github.com/hyperledger/fabric/common/crypto"
	//"github.com/hyperledger/fabric/common/localmsp"
	fsw "github.com/hyperledger/fabric/bccsp/sw"
	peercommon "github.com/hyperledger/fabric/peer/common"
)

const (
	//configtx.pb.go成员对象中的json tag值
	ConfigEnvelope_Config string = "config"
	ConfigEnvelope_LastUpdate string = "last_update"
	Config_Sequence string = "sequence"
	Config_ChannelGroup string = "channel_group"
	ConfigGroup_Version string = "version"
	ConfigGroup_Groups string = "groups"
	ConfigGroup_Values string = "values"
	ConfigGroup_Policies string = "policies"
	ConfigGroup_ModPolicy string = "mod_policy"

	ConfigValue_Value string = "value"
	ConfigValue_ModPolicy string = "mod_policy"

	ConfigPolicy_Policy string = "policy"
	ConfigPolicy_ModPolicy string = "mod_policy"

	OrdererGroupKey string = fconfig.OrdererGroupKey
	//...


	SEPARATOR string = "."
	SIGNCERTS_DIR string = "signcerts"
	KEYSTORE_DIR string = "keystore"
)

//TODO:
//1.怎么找到配置项，以最简单的形式提供修改配置项的值
//2.怎么更简单的签名，从原配置块中获取应该有的策略，然后形成签名spec，去签名。还有，如何签名？是通过网络分布式的签，还是在一个节点上集中签
//3.fabric多版本的支持
func main() {

	conf, err := getconfig()
	if err != nil {
		fmt.Printf("获取config.json配置失败, err: %s\n", err)
		return
	}

	blockdata, err := peerchannelfetchnewestconfigblock()
	if err != nil {
		fmt.Println(err)
		return
	}

	//1.找出原有配置信息
	//把配置块Unmarshal成Block，进而分解其中的Envelope（Block.Data.data[0]），该Envelope为一个CONFIG_UPDATE交易
	//分解Envelope中的ConfigEnvelope(Envelope.payload.data)，这里的配置包含了之前的所有配置信息。
	now_config := getconfigfromconfigblock(blockdata)
	if now_config == nil {
		fmt.Println("get config from configblock error")
		return
	}
	new_config := getconfigfromconfigblock(blockdata)

	//根据配置路径，找到指定的项，
	if !strings.Contains(modify_config_path, ConfigEnvelope_Config+SEPARATOR+Config_ChannelGroup+SEPARATOR) {
		fmt.Println("wrong config path")
		return
	}

	configpaths := strings.Split(modify_config_path, SEPARATOR);
	//最少是3层，如config.channel_group.mod_policy
	if len(configpaths) < 3 {
		fmt.Println("wrong config path")
		return
	}

	fmt.Println("config path:")
	fmt.Println(configpaths)

	//修改值，只会修改这4类值
	var configgroup *cb.ConfigGroup
	var configgroups map[string]*cb.ConfigGroup
	var configvalues map[string]*cb.ConfigValue
	var configpolicys map[string]*cb.ConfigPolicy
	var mod_policy string
	config_type := -1

	//groups.Orderer.values.KafkaBrokers
	//结果：
	//configgroup为上级的ConfigGroup
	//对应类型的值中保存着相应的要处理的值
	findconfig := func(path string) int {
		switch(path) {
		case ConfigGroup_Groups:
			if config_type == 0 {
				configgroups = configgroup.Groups
			}else {
				//最先开始的赋值的地方
				configgroups = new_config.ChannelGroup.Groups
			}
			config_type = 0
		//修改配置只可能是以下的3种类型
		case ConfigGroup_Values:
			if config_type == 0 {
				configvalues = configgroup.Values
			}else {
				configvalues = new_config.ChannelGroup.Values
				configgroup = new_config.ChannelGroup
			}
			config_type = 1
		case ConfigGroup_Policies:
			if config_type == 0 {
				configpolicys = configgroup.Policies
			}else {
				configpolicys = new_config.ChannelGroup.Policies
				configgroup = new_config.ChannelGroup
			}
			config_type = 2
		case ConfigGroup_ModPolicy:
			if config_type == 0 {
				mod_policy = configgroup.ModPolicy
			}else {
				mod_policy = new_config.ChannelGroup.ModPolicy
				configgroup = new_config.ChannelGroup
			}
			config_type = 3
		default:
			//只可能是自定义的group的key，如Orderer/Application/组织名等
			if config_type == 0 {
				configgroup = configgroups[path]
			}else {
				fmt.Println("wrong config path, please check")
				return -2
			}
		}

		return config_type
	}

	var index int
	var path string
	configpaths = configpaths[2:]
	for index, path = range configpaths {
		if config_type = findconfig(path); config_type != 0 { break }
	}

	//如果不是修改mod_policy，则应该还有2个path
	if (config_type != 3 && len(configpaths[index:]) < 3) {
		fmt.Println("config path is wrong, not precise")
		return
	}
	if config_type < 1 || config_type > 3 {
		fmt.Println("after findconfig, wrong config type,it should be 1,2 or 3")
		return
	}

	var leafconfigkey string
	if config_type == 1 {
		leafconfigkey = configpaths[index+1]
		if configpaths[index+2] == ConfigValue_Value {
			//最终要修改Value的值本身value
			err := findandsetvalue(leafconfigkey, modify_config_value, configvalues[leafconfigkey])
			if err != nil {
				fmt.Printf("findandsetvalue err: %s\n", err)
				return
			}
		}else if configpaths[index+2] == ConfigValue_ModPolicy {
			//最终要修改Value的修改策略mod_policy
			configvalues[leafconfigkey].ModPolicy = modify_config_value
		}else {
			fmt.Printf("config path is wrong, it should end with %s or %s\n",ConfigValue_ModPolicy, ConfigValue_Value)
			return
		}
	}else if config_type == 2 {
		fmt.Println("功能暂未实现")
		return
	}else if config_type == 3 {
		fmt.Println("功能暂未实现")
		return
	}

	//2.形成新的ConfigUpdateEnvelope
	//可以参考Envelope.payload.data.last_update，该结构是一个Envelope，但是一个升级配置的Envelope，
	//其中Envelope.payload.data.last_update.payload.data即为一个ConfigUpdateEnvelope，
	//升级的原始数据即是ConfigUpdateEnvelope.config_update
	//签名为ConfigUpdateEnvelope.signatures
	configupdate, err := update.Compute(now_config, new_config)
	if err != nil {
		fmt.Printf("Compute error: %s\n", err)
		return
	}

	configupdate.ChannelId = channelid

	configupdateenvelope := &cb.ConfigUpdateEnvelope{}
	header   := &cb.Header{}
	channelheader := &cb.ChannelHeader{}

	channelheader.Type = int32(cb.HeaderType_CONFIG_UPDATE)
	channelheader.ChannelId = channelid
	header.ChannelHeader, err = proto.Marshal(channelheader)
	if err != nil {
		fmt.Printf("marshaling channelheader error: %s\n", err)
		return
	}

	configupdateenvelope.ConfigUpdate, err = proto.Marshal(configupdate)
	if err != nil {
		fmt.Printf("marshaling configupdate error: %s\n", err)
		return
	}

	//3.根据2步生成的Envelope，进行签名，形成新的升级配置的pb文件
	//设置环境变量
	orderersigner, err := GetSigner(core_peer_localmspid_value_orderer, core_peer_mspconfigpath_value_orderer_admin)
	if err != nil {
		fmt.Printf("Get orderer Signer error: %s\n", err)
		return
	}
	sigHeader, err := orderersigner.NewSignatureHeader()
	if err != nil {
		fmt.Printf("orderer Signer NewSignatureHeader error: %s\n", err)
		return
	}
	configSig := &cb.ConfigSignature{
		SignatureHeader: fprotoutils.MarshalOrPanic(sigHeader),
	}
	configSig.Signature, err = orderersigner.Sign(util.ConcatenateBytes(configSig.SignatureHeader, configupdateenvelope.ConfigUpdate))

	configupdateenvelope.Signatures = append(configupdateenvelope.Signatures, configSig)

	signedenvelope, err := fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, orderersigner, configupdateenvelope, 0, 0)
	if err != nil {
		fmt.Printf("CreateSignedEnvelope err: %s\n", err)
		return
	}

	signedenvelopedata, err := proto.Marshal(signedenvelope)
	if err != nil {
		fmt.Printf("marshal signedenvelope error: %s\n", err)
		return
	}
	ioutil.WriteFile(signed_envelope_file, signedenvelopedata, 0660)

	//4.发送给orderer
	//参考peer/channel/update.go
	var bc peercommon.BroadcastClient
	//os.Setenv(orderer_address)
	//bc, err = peercommon.GetBroadcastClient()//v1.2，需要设置一些环境变量
	bc, err = peercommon.GetBroadcastClient(orderer_address, true, core_peer_tls_rootcert_file_value)//v1.0
	if err != nil {
		fmt.Printf("GetBroadcastClient error: %s\n", err)
		return
	}

	err = bc.Send(signedenvelope)
	if err != nil {
		fmt.Printf("Send error: %s\n", err)
		return
	}
	bc.Close()
}

func findandsetvalue(leafkey, leafjsonvalue string, configvalue *cb.ConfigValue) error {
	var err error
	switch leafkey {
	case fconfig.KafkaBrokersKey:
		brokers := ab.KafkaBrokers{}
		err = json.Unmarshal([]byte(leafjsonvalue), &brokers)
		if err != nil { return err }
		configvalue.Value, err = proto.Marshal(&brokers)
		if err != nil { return err }
	case fconfig.BatchSizeKey:
		batchsize := ab.BatchSize{}
		err = json.Unmarshal([]byte(leafjsonvalue), &batchsize)
		if err != nil { return err }
		configvalue.Value, err = proto.Marshal(&batchsize)
		if err != nil { return err }
	default:
		return fmt.Errorf("指定配置项修改功能暂未实现")
	}

	return nil
}

func getconfigfromconfigblock(configblockdata []byte) *cb.Config {
	configBlock, err := fprotoutils.GetBlockFromBlockBytes(configblockdata)
	if err != nil {
		fmt.Println("GetBlockFromBlockBytes")
		return nil
	}

	envelopeData := configBlock.Data.Data[0]
	envelope, err := fprotoutils.UnmarshalEnvelope(envelopeData)
	if err != nil {
		fmt.Println("UnmarshalEnvelope")
		return nil
	}

	configEnvelope := &cb.ConfigEnvelope{}
	_, err = fprotoutils.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_CONFIG, configEnvelope)
	if err != nil {
		fmt.Println("UnmarshalEnvelopeOfType")
		return nil
	}

	//data.data[0].payload.data.config
	return configEnvelope.Config
}

//peer channel fetch newest config block
func peerchannelfetchnewestconfigblock(conf *config) ([]byte, error) {
	if conf == nil {
		return nil, fmt.Errorf("conf is nil")
	}
	//v1.0 - 至下文建立client对象，v1.2有专门函数建立，不用这样一步一步来
	var opts []grpc.DialOption
	var tls = true//暂时默认tls为true，之后通过配置文件来
	if tls {
		if conf.BasicInfo["orderer_tls_rootcert"] != "" {
			creds, err := credentials.NewClientTLSFromFile(core_peer_tls_rootcert_file_value, "")
			if err != nil {
				return nil, fmt.Errorf("Error connecting to %s due to %s", orderer_address, err)
			}
			opts = append(opts, grpc.WithTransportCredentials(creds))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(orderer_address, opts...)
	if err != nil { return nil, err }

	client, err := ab.NewAtomicBroadcastClient(conn).Deliver(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("Error connecting due to  %s", err)
	}

	position := &ab.SeekPosition{Type: &ab.SeekPosition_Newest{Newest: &ab.SeekNewest{}}}
	seekInfo := &ab.SeekInfo{
		Start:    position,
		Stop:     position,
		Behavior: ab.SeekInfo_BLOCK_UNTIL_READY,
	}
	version := int32(0)
	epoch := uint64(0)
	signer, err := GetSigner(core_peer_localmspid_value_peer, core_peer_mspconfigpath_value_peer_admin)
	if err != nil { return nil, err }
	envelope, err := fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, seekInfo, version, epoch)
	if err != nil {
		return nil, fmt.Errorf("Error signing envelope1:  %s", err)
	}

	err = client.Send(envelope)
	if err != nil {
		return nil, fmt.Errorf("Error Send newest block due to  %s", err)
	}

	msg, err := client.Recv()
	if err != nil {
		return nil, fmt.Errorf("Error receiving1: %s", err)
	}

	var block *cb.Block
	switch t := msg.Type.(type) {
	case *ab.DeliverResponse_Status:
		return nil, fmt.Errorf("can't read the block: %v", t)
	case *ab.DeliverResponse_Block:
		fmt.Printf("Received block: %v\n", t.Block.Header.Number)
		client.Recv()
		block = t.Block
	default:
		return nil, fmt.Errorf("response error: unknown type %T", t)
	}

	lastconfigblocknum, err := fprotoutils.GetLastConfigIndexFromBlock(block)
	if err != nil { return nil, err }

	seekInfo.Start.Type = &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: lastconfigblocknum}}
	seekInfo.Stop.Type = &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: lastconfigblocknum}}
	envelope, err = fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, seekInfo, version, epoch)
	if err != nil {
		return nil, fmt.Errorf("Error signing envelope2:  %s", err)
	}
	err = client.Send(envelope)
	if err != nil {
		return nil, fmt.Errorf("Error Send specified block due to  %s", err)
	}

	msg, err = client.Recv()
	if err != nil {
		return nil, fmt.Errorf("Error receiving2: %s", err)
	}
	switch t := msg.Type.(type) {
	case *ab.DeliverResponse_Status:
		return nil, fmt.Errorf("can't read the block: %v", t)
	case *ab.DeliverResponse_Block:
		fmt.Printf("Received block: %v\n", t.Block.Header.Number)
		client.Recv()
		block = t.Block
	default:
		return nil, fmt.Errorf("response error: unknown type %T", t)
	}

	blockdata, err := proto.Marshal(block)
	if err != nil { return nil, fmt.Errorf("Marshal block error: %s", err) }
	if err = ioutil.WriteFile("./meconfig_config_block.pb", blockdata, 0644); err != nil {
		return nil, err
	}
	conn.Close()
	//由于对比的时候要保证两份block，因此这里返回[]byte格式的block
	return blockdata, nil
}

//这里暂时只限定，只认x509，ecdsa的，非加密的证书
//哈希暂时只支持sha2 - 256
//这些也是默认的选项
//实现fabric/common/crypto/signer.go中定义的LocalSigner接口
type MspSigner struct {
	mspid string
	cert *x509.Certificate
	privatekey *ecdsa.PrivateKey
	hasher hash.Hash
}

func GetSigner(msp_id, msp_path string) (*MspSigner, error) {
	signer := &MspSigner{
		mspid: msp_id,
		hasher: sha256.New(),
	}
	//1.读取证书目录下的证书
	signcerts_dir := filepath.Join(msp_path, SIGNCERTS_DIR)
		_, err := os.Stat(signcerts_dir)
	if os.IsNotExist(err) {
		return nil, err
	}

	signcerts := make([][]byte, 0)
	files, err := ioutil.ReadDir(signcerts_dir)
	if err != nil {
		return nil, fmt.Errorf("Could not read directory %s, err %s", err, signcerts_dir)
	}

	for _, f := range files {
		if f.IsDir() { continue }

		fullName := filepath.Join(signcerts_dir, string(filepath.Separator), f.Name())
		fileBytes, err := ioutil.ReadFile(fullName)
		if err != nil {
			fmt.Printf("Could not read file %s, err %s\n", fullName, err)
			continue
		}
		//这里只是检查一下
		certbytes, _ := pem.Decode(fileBytes)
		if certbytes == nil {
			fmt.Printf("No pem content for file %s\n", fullName)
			continue
		}

		signcerts = append(signcerts, fileBytes)
		break
	}

	if len(signcerts) == 0 {
		return nil, fmt.Errorf("Could not load a valid signer certificate from directory %s", signcerts_dir)
	}

	pemcert, _ := pem.Decode(signcerts[0])
	signer.cert, err = x509.ParseCertificate(pemcert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("getIdentityFromBytes error: failed to parse x509 cert, err %s", err)
	}

	//2.根据证书获取证书对应的私钥文件名，并读取，生成私钥对象
	pubkey, ok := signer.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pubkey is nil, check cert")
	}

	pubkeyraw := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	temphash := sha256.New()
	temphash.Write(pubkeyraw)
	pubkeyraw_hash := temphash.Sum(nil)
	privkey_name := hex.EncodeToString(pubkeyraw_hash) + "_sk"
	privkey_path := filepath.Join(msp_path, KEYSTORE_DIR, privkey_name)
	privkey_raw, err := ioutil.ReadFile(privkey_path)
	if err != nil {
		return nil, fmt.Errorf("Failed loading private key [%s]: [%s].", privkey_path, err)
	}
	//第二个参数是密码，这里给nil，表示假设证书非加密
	privkey, err := fbccsputils.PEMtoPrivateKey(privkey_raw, nil)
	if err != nil {
		return nil, fmt.Errorf("get private key err: %s", err)
	}

	signer.privatekey, ok = privkey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("privatekey is not ecdsa.PrivateKey")
	}

	return signer, nil
}

func (ms *MspSigner) NewSignatureHeader() (*cb.SignatureHeader, error) {
	pb := &pem.Block{Bytes: ms.cert.Raw}
	pemBytes := pem.EncodeToMemory(pb)
	if pemBytes == nil {
		return nil, fmt.Errorf("Encoding of identitiy failed")
	}
	sId := &mb.SerializedIdentity{Mspid: ms.mspid, IdBytes: pemBytes}
	creatorIdentityRaw, err := proto.Marshal(sId)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal a SerializedIdentity structure for identity %s, err %s", ms.mspid, err)
	}

	nonce, err := fcrypto.GetRandomNonce()
	if err != nil {
		return nil, fmt.Errorf("Failed creating nonce [%s]", err)
	}

	sh := &cb.SignatureHeader{}
	sh.Creator = creatorIdentityRaw
	sh.Nonce = nonce

	return sh, nil
}

func (ms *MspSigner) Sign(msg []byte) (signature []byte, err error) {
	ms.hasher.Reset()
	ms.hasher.Write(msg)
	digest := ms.hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, ms.privatekey, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = fsw.ToLowS(&ms.privatekey.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return fsw.MarshalECDSASignature(r, s)
}

type MEconfig struct {
	BasicInfo [string]string `json:"basic_info,omitempty"`
	ConfigInfo [string]interface{} `json:"config_info,omitempty"`
	Option [string]bool `json:"option,omitempty"`
}

func getMEConfig() (*MEConfig, error) {
	configbyte, err := ioutil.ReadFile("./config.json")
	if err != nil { return nil, err }

	conf := &MEConfig{}
	err = json.Unmarshal(configbyte, conf)
	if err != nil { return nil, err }
	return conf, nil
}

func getConfigEnvelopeData(conf *MEConfig) ([]byte, error) {
	var 
	if conf.Option["fetch"] {
	
	}else {
	
	}
}

