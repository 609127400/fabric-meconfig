
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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	MECONFIG_FILE_PATH string = "./"
	MECONFIG_FILE string = "meconfig"
	FLAG_NOSET string = "noset"
)

type MODE int
const (
	UNKNOWN_MODE MODE = 0
	FETCH  MODE = 0x01
	DELTA  MODE = 0x02
	SIGN   MODE = 0x04
	COMMIT MODE = 0x08
	F    MODE = FETCH
	FD   MODE = FETCH | DELTA
	FDS  MODE = FETCH | DELTA | SIGN
	S    MODE = SIGN
	SC   MODE = SIGN | COMMIT
	C    MODE = COMMIT
	FDSC MODE = FETCH | DELTA | SIGN | COMMIT
)

var MODE_name = map[MODE]string{
	F:   "f",
	FD: "fd",
	FDS: "fds",
	S: "s",
	SC: "sc",
	C: "c",
	FDSC: "fdsc",
	UNKNOWN_MODE: "unknown mode",
}

var MODE_value = map[string]MODE{
	"f": F,
	"fd": FD,
	"fds": FDS,
	"s": S,
	"sc": SC,
	"c": C,
	"fdsc": FDSC,
	"unknown mode": UNKNOWN_MODE,
}

var mode_flag string
var encode_flag string
var decode_flag string
var is_save bool

//TODO:
//1.怎么找到配置项，以最简单的形式提供修改配置项的值
//2.怎么更简单的签名，从原配置块中获取应该有的策略，然后形成签名spec，去签名。还有，如何签名？是通过网络分布式的签，还是在一个节点上集中签
//3.fabric多版本的支持
func main() {
	mecmd := &cobra.Command{
	    Use: "meconfig",
	    Short: "more easy to modify config of hyperledger-fabric's channel",
	    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		viper.SetConfigName(MECONFIG_FILE)
		viper.AddConfigPath(MECONFIG_FILE_PATH)
		err := viper.ReadInConfig()
		if err != nil { return fmt.Errorf("Fatal error config file: %s", err) }
		return nil
	    },
	    RunE: func(cmd *cobra.Command, args []string) error {
		mode := MODE_value[mode_flag]
		if mode == UNKNOWN_MODE { return fmt.Errorf("unknown mode") }
		err = mode.do(conf)
		if err != nil { return fmt.Errorf("do error: %s", err) }
		return nil
	    },
	    Version: "1.0",
	}
	flags := mecmd.PersistentFlags()
	flags.StringVarP(&mode_flag, "mode", "m", FLAG_NOSET, "mode of operation of config")
	flags.StringVarP(&encode_flag, "encode", "e", FLAG_NOSET, "Converts a JSON document to proto")
	flags.StringVarP(&decode_flag, "decode", "d", FLAG_NOSET, "Converts a proto message to JSON")
	flags.BoolVarP(&is_save, "save", "s", false, "if save artificial config file during operation")

	if mecmd.Execute() != nil {
		os.Exit(1)
	}
}

func findAndSetValue(leafkey string, leafjsonvalue interface{}, configvalue *cb.ConfigValue) error {
	if leafkey == "" || leafjsonvalue == nil || configvalue == nil {
		return fmt.Errorf("findAndSetValue args is nil")
	}

	var err error
	var data []byte
	data, err = json.Marshal(leafjsonvalue)
	if err != nil { return err }

	switch leafkey {
	case fconfig.KafkaBrokersKey:
		brokers := &ab.KafkaBrokers{}
		err = json.Unmarshal(data, brokers)
		if err != nil { return err }
		data, err = proto.Marshal(brokers)
		if err != nil { return err }
	case fconfig.BatchSizeKey:
		batchsize := &ab.BatchSize{}
		err = json.Unmarshal(data, batchsize)
		if err != nil { return err }
		data, err = proto.Marshal(batchsize)
		if err != nil { return err }
	default:
		return fmt.Errorf("指定配置项修改功能暂未实现")
	}

	configvalue.Value = data
	return nil
}

func getConfigFromBlock(configblockdata []byte) *cb.Config {
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
func peerChannelFetchNewestConfigblock(conf *MEConfig) ([]byte, error) {
	if conf == nil {
		return nil, fmt.Errorf("conf is nil")
	}
	//v1.0 - 至下文建立client对象，v1.2有专门函数建立，不用这样一步一步来
	var opts []grpc.DialOption
	var tls = true//暂时默认tls为true，之后通过配置文件来
	if tls {
		if conf.BasicInfo["orderer_tls_rootcert"] != "" {
			creds, err := credentials.NewClientTLSFromFile(conf.BasicInfo["orderer_tls_rootcert"], "")
			if err != nil {
				return nil, fmt.Errorf("Error connecting to %s due to %s", conf.BasicInfo["orderer_endpoint"] , err)
			}
			opts = append(opts, grpc.WithTransportCredentials(creds))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(conf.BasicInfo["orderer_endpoint"], opts...)
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
	channelid := conf.BasicInfo["channel_id"]
	signer, err := getSigner(conf)
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

	conn.Close()
	//由于对比的时候要保证两份block，因此这里返回[]byte格式的block
	return blockdata, nil
}

//这里暂时只限定，只认x509，ecdsa的，非加密的证书
//哈希暂时只支持sha2 - 256
//这些也是默认的选项
//实现fabric/common/crypto/signer.go中定义的LocalSigner接口
type mspSigner struct {
	mspid string
	cert *x509.Certificate
	privatekey *ecdsa.PrivateKey
	hasher hash.Hash
}

func getSigner(conf *MEConfig) (*mspSigner, error) {
	if conf == nil {
		return nil, fmt.Errorf("conf is nil")
	}
	var msp_id, msp_path string
	var ok bool
	if msp_id, ok = conf.BasicInfo["signmsp_id"]; (!ok || msp_id == "") {
		msp_id = conf.BasicInfo["localmsp_id"]
	}
	if msp_path, ok = conf.BasicInfo["signmsp_path"]; (!ok || msp_path == "") {
		msp_path = conf.BasicInfo["localmsp_path"]
	}
	if msp_id == "" || msp_path == "" {
		return nil, fmt.Errorf("msp_id or msp_path is nil")
	}
	signer := &mspSigner{
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
		return nil, fmt.Errorf("Could not read dir %s, err %s", err, signcerts_dir)
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
		return nil, fmt.Errorf("can not load a valid signer cert from %s", signcerts_dir)
	}

	pemcert, _ := pem.Decode(signcerts[0])
	signer.cert, err = x509.ParseCertificate(pemcert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 cert, err %s", err)
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
		return nil, fmt.Errorf("Failed loading private key[%s]: [%s].", privkey_path, err)
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

func (ms *mspSigner) NewSignatureHeader() (*cb.SignatureHeader, error) {
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

func (ms *mspSigner) Sign(msg []byte) (signature []byte, err error) {
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

type MEConfig struct {
	Option       map[string]bool `json:"option,omitempty"`
	BasicInfo    map[string]string `json:"basic_info,omitempty"`
	FetchConfig  map[string]string `json:"fetch_config,omitempty"`
	DeltaConfig  map[string]interface{} `json:"delta_config,omitempty"`
	SignConfig   map[string]string `json:"sign_config,omitempty"`
	CommitConfig map[string]string `json:"commit_config,omitempty"`
	SaveConfig   map[string]string `json:"save_config,omitempty"`
}

func getMEConfig() (*MEConfig, error) {
	configbyte, err := ioutil.ReadFile(MECONFIG_FILE_PATH)
	if err != nil { return nil, err }

	conf := &MEConfig{}
	err = json.Unmarshal(configbyte, conf)
	if err != nil { return nil, err }
	return conf, nil
}

func getMode(conf *MEConfig) MODE {
	if conf == nil { return UNKNOWN_MODE }

	is_fetch  := conf.Option["fetch"]
	is_delta  := conf.Option["delta"]
	is_sign   := conf.Option["sign"]
	is_commit := conf.Option["commit"]
	if is_fetch  && !is_delta && !is_sign && !is_commit { return F    }
	if is_fetch  && is_delta  && !is_sign && !is_commit { return FD   }
	if is_fetch  && is_delta  && is_sign  && !is_commit { return FDS  }
	if !is_fetch && !is_delta && is_sign  && !is_commit { return S    }
	if !is_fetch && !is_delta && is_sign  && is_commit  { return SC   }
	if !is_fetch && !is_delta && !is_sign && is_commit  { return C    }
	if is_fetch  && is_delta  && is_sign  && is_commit  { return FDSC }

	return UNKNOWN_MODE
}

func adjustMEConfigByCmdLine(conf *MEConfig) error {
	if conf == nil { return fmt.Errorf("conf is nil") }

	notset := "netset"
	save := notset
	mode := notset
	args := os.Args[1:]
	argslen := len(args)
	errHander := func(msg string) error {
		return fmt.Errorf("err: %s.\nusage example:[meconfig --mode fds -s].", msg)
	}

	for i := 0; i < argslen; i++ {
		v := args[i]
		if v == "-m" || v == "--mode" {
			if i < argslen - 1 {
				mode = args[i+1]
				i++//跳过flag的值
			}else {
				return errHander("please set mode value")
			}
		}else if v == "-s" || v == "--save" {
			save = ""
		}else {
			return errHander("unknown flag")
		}
	}

	if mode != notset {
		m := MODE_value[mode]
		if m == UNKNOWN_MODE { return errHander("mode is unknown") }

		if FETCH&m == FETCH { conf.Option["fetch"] = true }
		if DELTA&m == DELTA { conf.Option["delta"] = true }
		if SIGN&m == SIGN { conf.Option["sign"] = true }
		if COMMIT&m == COMMIT { conf.Option["commit"] = true }
	}
	if save != notset {
		conf.Option["save"] = true
	}

	return nil
}

func fetch(conf *MEConfig) ([]byte, error) {
	fmt.Println("start to fetch...")
	if conf == nil { return nil, fmt.Errorf("fetch args is nil") }

	var data []byte
	var err error

	if conf.FetchConfig["from"] == "channel" {
		fmt.Println("fetch config block from channel...")
		data, err = peerChannelFetchNewestConfigblock(conf)
		if err != nil { return nil, err }
	}else {
		file := conf.FetchConfig["configblock_path"]
		fmt.Printf("fetch config block from file [%s]\n", file)
		data, err = ioutil.ReadFile(file)
		if err != nil { return nil, err }
	}

	return data, nil
}

func delta(blockdata []byte, conf *MEConfig) (*cb.Envelope, error) {
	fmt.Println("start to delta...")
	var err error
	if blockdata == nil || conf == nil {
		return nil, fmt.Errorf("blockdata or conf is nil")
	}
	//1.找出原有配置信息
	//把配置块Unmarshal成Block，进而分解其中的Envelope（Block.Data.data[0]），该Envelope为一个CONFIG_UPDATE交易
	//分解Envelope中的ConfigEnvelope(Envelope.payload.data)，这里的配置包含了之前的所有配置信息。
	now_config := getConfigFromBlock(blockdata)
	if now_config == nil {
		return nil, fmt.Errorf("get config from configblock error")
	}
	new_config := getConfigFromBlock(blockdata)

	//计算后，configgroup为包含配置值对象的ConfigGroup
	//configgroup中包含工具可能使用到的信息，如连接orderer的tls证书等
	//但是始终都需要使用本地的东西，如签名的私钥，所以干脆都使用本地的，而不使用configgroup中的
	//修改值，只会修改这4类值
	//例子 path=config.channel_group.groups.Orderer.values.KafkaBrokers.value
	var configgroup *cb.ConfigGroup
	var configgroups map[string]*cb.ConfigGroup
	var configvalues map[string]*cb.ConfigValue
	var configpolicys map[string]*cb.ConfigPolicy
	var mod_policy string
	config_type := -1
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
			}
			config_type = 1
		case ConfigGroup_Policies:
			if config_type == 0 {
				configpolicys = configgroup.Policies
			}else {
				configpolicys = new_config.ChannelGroup.Policies
			}
			config_type = 2
		case ConfigGroup_ModPolicy:
			if config_type == 0 {
				mod_policy = configgroup.ModPolicy
			}else {
				mod_policy = new_config.ChannelGroup.ModPolicy
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

	fixed_prefix := ConfigEnvelope_Config+SEPARATOR+Config_ChannelGroup+SEPARATOR
	var configpaths []string
	var path string
	var index int
	kvs := conf.DeltaConfig["delta_kvs"].(map[string]interface{})
	for cp, cv := range kvs {
		//根据配置路径，找到指定的项，
		if !strings.Contains(cp, fixed_prefix) {
			fmt.Printf("wrong config path[%s], it's should be %s...\n", cp, fixed_prefix)
			continue
		}
		configpaths = strings.Split(cp, SEPARATOR);
		//最少是3层，如config.channel_group.mod_policy
		if len(configpaths) < 3 {
			fmt.Printf("wrong config path[%s], it's fewer than 3\n", cp)
			continue
		}
		fmt.Printf("config path to update:[%s]\n", cp)
		//去掉config.channel_group，剩下groups.Orderer.values.KafkaBrokers.value
		configpaths = configpaths[2:]

		config_type = -1//恢复类型
		for index, path = range configpaths {
			//应该遍历至values
			if config_type = findconfig(path); config_type != 0 { break }
		}

		//如果不是修改mod_policy，则应该还有2个path
		if (config_type != 3 && len(configpaths[index+1:]) < 2) {
			fmt.Println("config path is wrong, not precise")
			continue
		}
		if config_type < 1 || config_type > 3 {
			fmt.Println("after findconfig, wrong config type,it should be 1,2 or 3")
			continue
		}

		if config_type == 1 {
			path = configpaths[index+1]
			cp = configpaths[index+2]
			if  cp == ConfigValue_Value {
				//最终要修改Value的值本身value
				configvalue, ok := configvalues[path]
				if !ok {
					fmt.Printf("config[%s] do not exits\n", path)
					continue
				}
				err := findAndSetValue(path, cv, configvalue)
				if err != nil {
					fmt.Printf("findAndSetValue[%s] err: %s\n", path, err)
					continue
				}
			}else if cp == ConfigValue_ModPolicy {
				//最终要修改Value的修改策略mod_policy
				configvalues[path].ModPolicy = cv.(string)
			}else {
				fmt.Printf("config path is wrong, should end with %s or %s\n",ConfigValue_ModPolicy, ConfigValue_Value)
				continue
			}
		}else if config_type == 2 {
			return nil, fmt.Errorf("功能暂未实现")
		}else if config_type == 3 {
			return nil, fmt.Errorf("功能暂未实现")
		}
	}//end for

	//2.形成新的ConfigUpdateEnvelope
	//可以参考Envelope.payload.data.last_update，该结构是一个Envelope，但是一个升级配置的Envelope，
	//其中Envelope.payload.data.last_update.payload.data即为一个ConfigUpdateEnvelope，
	//升级的原始数据即是ConfigUpdateEnvelope.config_update
	//签名为ConfigUpdateEnvelope.signatures
	configupdate, err := update.Compute(now_config, new_config)
	if err != nil {
		return nil, fmt.Errorf("Compute error: %s", err)
	}
	configupdate.ChannelId = conf.BasicInfo["channel_id"]

	ch := &cb.ChannelHeader{
		Type: int32(cb.HeaderType_CONFIG_UPDATE),
		ChannelId: configupdate.ChannelId,
	}

	header   := &cb.Header{}
	header.ChannelHeader, err = proto.Marshal(ch)
	if err != nil {
		return nil, fmt.Errorf("marshaling channelheader error: %s", err)
	}

	configupdateenvelope := &cb.ConfigUpdateEnvelope{}
	configupdateenvelope.ConfigUpdate, err = proto.Marshal(configupdate)
	if err != nil {
		return nil, fmt.Errorf("marshaling configupdate error: %s", err)
	}
	data, err := proto.Marshal(configupdateenvelope)
	if err != nil {
		return nil, fmt.Errorf("marshaling configupdateenvelope error: %s", err)
	}
	payload, err := proto.Marshal(&cb.Payload{ Data: data })
	if err != nil {
		return nil, fmt.Errorf("marshaling payload error: %s", err)
	}

	envelope := &cb.Envelope{ Payload: payload }

	return envelope, nil
}

func sign(envelope *cb.Envelope, conf *MEConfig) (*cb.Envelope, error) {
	fmt.Println("start to sign...")
	if envelope == nil || conf == nil {
		return nil, fmt.Errorf("args is nil")
	}

	var err error
	payload := &cb.Payload{}
	if err = proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, fmt.Errorf("Unmarshal Payload err: %s", err)
	}
	cue := &cb.ConfigUpdateEnvelope{}
	if err = proto.Unmarshal(payload.Data, cue); err != nil {
		return nil, fmt.Errorf("Unmarshal Payload.Data err: %s", err)
	}

	signer, err := getSigner(conf)
	if err != nil { return nil, err }

	sh, err := signer.NewSignatureHeader()
	if err != nil { return nil, err }

	cs := &cb.ConfigSignature{ SignatureHeader: fprotoutils.MarshalOrPanic(sh) }
	cs.Signature, err = signer.Sign(util.ConcatenateBytes(cs.SignatureHeader, cue.ConfigUpdate))

	cue.Signatures = append(cue.Signatures, cs)

	channelid := conf.BasicInfo["channel_id"]
	signedenvelope, err := fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, cue, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateSignedEnvelope err: %s", err)
	}

	return signedenvelope, nil
}

func commit(envelope *cb.Envelope, conf *MEConfig) error {
	fmt.Println("start to commit...")
	if envelope == nil || conf == nil { return fmt.Errorf("commit args is nil") }
	//os.Setenv(orderer_address)
	//bc, err = peercommon.GetBroadcastClient()//v1.2，需要设置一些环境变量
	orderer_endpoint := conf.BasicInfo["orderer_endpoint"]
	orderer_tls_rootcert := conf.BasicInfo["orderer_tls_rootcert"]
	if orderer_endpoint == "" || orderer_tls_rootcert == "" {
		return fmt.Errorf("orderer_endpoint or orderer_tls_rootcert is nil")
	}
	bc, err := peercommon.GetBroadcastClient(orderer_endpoint, true, orderer_tls_rootcert)//v1.0
	if err != nil { return fmt.Errorf("GetBroadcastClient error: %s", err) }

	err = bc.Send(envelope)
	if err != nil { return fmt.Errorf("Send error: %s\n", err) }

	bc.Close()
	return nil
}

func f_mode(conf *MEConfig) ([]byte, error) {
	blockdata, err := fetch(conf)
	if err != nil { return nil, err }
	is_save := conf.Option["save"]
	if is_save && conf.FetchConfig["from"] == "channel" {
		if err = ioutil.WriteFile(conf.FetchConfig["fetch_file"], blockdata, 0644); err != nil {
			return nil, fmt.Errorf("write fetch_file err: %s", err)
		}
	}
	return blockdata, nil
}

func fd_mode(conf *MEConfig) (*cb.Envelope, error) {
	blockdata, err := f_mode(conf)
	if err != nil { return nil, fmt.Errorf("fd_mode f_mode err: %s", err) }
	envelope, err := delta(blockdata, conf)
	if err != nil { return nil, fmt.Errorf("fd_mode delta err: %s", err) }
	data, err := proto.Marshal(envelope)
	if err != nil { return nil, fmt.Errorf("fd_mode marshal err: %s", err) }
	file := conf.DeltaConfig["delta_file"].(string)
	if file == "" {
		return nil, fmt.Errorf("fd_mode err: please set delta_config.delta_file")
	}
	err = ioutil.WriteFile(file, data, 0660)
	if err != nil { return nil, fmt.Errorf("fd_mode write file err: %s", err) }
	return envelope, nil
}

func fds_mode(conf *MEConfig) (*cb.Envelope, error) {
	blockdata, err := f_mode(conf)
	if err != nil { return nil, fmt.Errorf("f_mode err: %s", err) }
	envelope, err := delta(blockdata, conf)
	is_save := conf.Option["save"]
	if is_save {
		file := conf.DeltaConfig["delta_file"].(string)
		if file == "" { return nil, fmt.Errorf("fds_mode err: save is true but delta_config.delta_file is nil") }
		data, err := proto.Marshal(envelope)
		if err != nil { return nil, fmt.Errorf("fds_mode marshal err: %s", err) }
		err = ioutil.WriteFile(file, data, 0660)
		if err != nil { return nil, fmt.Errorf("fds_mode write file err: %s", err) }
	}

	signedenvelope, err := sign(envelope, conf)
	if err != nil { return nil, fmt.Errorf("fds_mode sign err: %s", err) }

	signedenvelopedata, err := proto.Marshal(signedenvelope)
	if err != nil { return nil, fmt.Errorf("marshal signedenvelope error: %s", err) }
	file := conf.SignConfig["sign_file"]
	if file == "" { return nil, fmt.Errorf("fds_mode err: please set sign_config.sign_file") }
	err = ioutil.WriteFile(file, signedenvelopedata, 0660)
	if err != nil { return nil, fmt.Errorf("write signedenvelope err: %s", err) }

	return signedenvelope, nil
}

func s_mode(conf *MEConfig) (*cb.Envelope, error) {
	var signedenvelope *cb.Envelope

	if conf.SignConfig["from"] == "file" {
		file := conf.SignConfig["sign_file"]
		if file == "" { return nil, fmt.Errorf("s_mode err: please set sign_config.sign_file") }
		data, err := ioutil.ReadFile(file)
		if err != nil { return nil, fmt.Errorf("s_mode read file err: %s", err) }

		envelope, err := fprotoutils.UnmarshalEnvelope(data)
		if err != nil { return nil, fmt.Errorf("s_mode unmarshal err: %s", err) }
		signedenvelope, err = sign(envelope, conf)
		if err != nil { return nil, fmt.Errorf("fds_mode sign err: %s", err) }
		signedenvelopedata, err := proto.Marshal(signedenvelope)
		if err != nil { return nil, fmt.Errorf("marshal signedenvelope err: %s", err) }
		err = ioutil.WriteFile(file, signedenvelopedata, 0660)
		if err != nil { return nil, fmt.Errorf("write signedenvelope err: %s", err) }
	}else {
		return nil, fmt.Errorf("s_mode err: please set sign_config's from='file' and set sign_file")
	}

	return signedenvelope, nil
}

func sc_mode(conf *MEConfig) error {
	signedenvelope, err := s_mode(conf)
	if err != nil { return fmt.Errorf("sc_mode s_mode err: %s", err) }

	return commit(signedenvelope, conf)
}

func c_mode(conf *MEConfig) error {
	if conf.CommitConfig["from"] == "file" {
		file := conf.CommitConfig["commit_file"]
		if file == "" { return fmt.Errorf("c_mode err: please set commit_config.commit_file") }
		data, err := ioutil.ReadFile(file)
		if err != nil { return fmt.Errorf("s_mode read file err: %s", err) }
		signedenvelope, err := fprotoutils.UnmarshalEnvelope(data)
		if err != nil { return fmt.Errorf("s_mode unmarshal err: %s", err) }

		return commit(signedenvelope, conf)
	}
	return fmt.Errorf("c_mode err: please set commit_config's from='file' and set commit_file")
}

func fdsc_mode(conf *MEConfig) error {
	blockdata, err := f_mode(conf)
	if err != nil { return fmt.Errorf("fdsc_mode f_mode err: %s", err) }
	envelope, err := delta(blockdata, conf)
	if err != nil { return fmt.Errorf("fdsc_mode delta err: %s", err) }
	is_save := conf.Option["save"]
	if is_save {
		data, err := proto.Marshal(envelope)
		if err != nil { return fmt.Errorf("fdsc_mode marshal err: %s", err) }
		file := conf.DeltaConfig["delta_file"].(string)
		if file == "" { return fmt.Errorf("fdsc_mode err: save is true but delta_config.delta_file is nil") }
		err = ioutil.WriteFile(file, data, 0660)
		if err != nil { return fmt.Errorf("fdsc_mode write file err: %s", err) }
	}

	signedenvelope, err := sign(envelope, conf)
	if err != nil { return fmt.Errorf("fdsc_mode sign err: %s", err) }
	if is_save {
		signedenvelopedata, err := proto.Marshal(signedenvelope)
		if err != nil { return fmt.Errorf("marshal signedenvelope err: %s", err) }
		file := conf.SignConfig["sign_file"]
		if file == "" { return fmt.Errorf("fdsc_mode err: save is true but sign_config.sign_file is nil") }
		err = ioutil.WriteFile(file, signedenvelopedata, 0660)
		if err != nil { return fmt.Errorf("write signedenvelope err: %s", err) }
	}

	err = commit(signedenvelope, conf)
	if err != nil { return fmt.Errorf("fdsc_mode commit err: %s", err) }

	return nil
}

func (m *MODE) do(conf *MEConfig) error {
	if conf == nil { return fmt.Errorf("do args is nil") }
	mode := *m
	var err error

	if mode == F {
		_, err = f_mode(conf)
	}else if mode == FD {
		_, err = fd_mode(conf)
	}else if mode == FDS {
		_, err = fds_mode(conf)
	}else if mode == S {
		_, err = s_mode(conf)
	}else if mode == SC {
		err = sc_mode(conf)
	}else if mode == C {
		err = c_mode(conf)
	}else if mode == FDSC {
		err = fdsc_mode(conf)
	}else {
		return fmt.Errorf("未知操作模式[%d]", mode)
	}

	return err
}

/*
//msgName要具体到某个库下的数据类型，该类型经过proto.RegisterType()注册过，在这里的proto.MessageType即可识别
func encode(msgName string, input, output *os.File) error {
	msgType := proto.MessageType(msgName)
	if msgType == nil {
		return errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	err := protolator.DeepUnmarshalJSON(input, msg)
	if err != nil {
		return errors.Wrapf(err, "error decoding input")
	}

	out, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrapf(err, "error marshaling")
	}

	_, err = output.Write(out)
	if err != nil {
		return errors.Wrapf(err, "error writing output")
	}

	return nil
}

func decode(msgName string, input, output *os.File) error {
	msgType := proto.MessageType(msgName)
	if msgType == nil {
		return errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	in, err := ioutil.ReadAll(input)
	if err != nil {
		return errors.Wrapf(err, "error reading input")
	}

	err = proto.Unmarshal(in, msg)
	if err != nil {
		return errors.Wrapf(err, "error unmarshaling")
	}

	err = protolator.DeepMarshalJSON(output, msg)
	if err != nil {
		return errors.Wrapf(err, "error encoding output")
	}

	return nil
}
*/
