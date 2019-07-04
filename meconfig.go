
package main

import(
	"fmt"
	"strings"
	"strconv"
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
	"reflect"

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
	fmsp "github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/common/tools/protolator"
	futil "github.com/hyperledger/fabric/common/util"
	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
	mb "github.com/hyperledger/fabric/protos/msp"
	pb "github.com/hyperledger/fabric/protos/peer"
	fupdate "github.com/hyperledger/fabric/common/tools/configtxlator/update"
	fcrypto "github.com/hyperledger/fabric/common/crypto"
	//"github.com/hyperledger/fabric/common/localmsp"
	fsw "github.com/hyperledger/fabric/bccsp/sw"
	peercommon "github.com/hyperledger/fabric/peer/common"
	fcauthdsl "github.com/hyperledger/fabric/common/cauthdsl"
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
var type_flag string
var is_m, is_s, is_e, is_d, is_t bool

//TODO:
//1.怎么找到配置项，以最简单的形式提供修改配置项的值
//2.怎么更简单的签名，从原配置块中获取应该有的策略，然后形成签名spec，去签名。还有，如何签名？是通过网络分布式的签，还是在一个节点上集中签
//3.fabric多版本的支持
func main() {
	mecmd := &cobra.Command{
		Use: "meconfig",
		Short: "more easy to modify config of hyperledger-fabric's channel",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			//检查flag
			is_m = mode_flag   != FLAG_NOSET
			is_e = encode_flag != FLAG_NOSET
			is_d = decode_flag != FLAG_NOSET
			is_t = type_flag   != FLAG_NOSET
			if is_m && !is_s && !is_e && !is_d && !is_t {     //meconfig -m xx
			}else if is_m && is_s && !is_e && !is_d && !is_t {//meconfig -m xx -s
			}else if !is_m && !is_s && is_e && !is_d && is_t {//meconfig -e xx -t xx
			}else if !is_m && !is_s && !is_e && is_d && is_t {//meconfig -d xx -t xx
			}else { return fmt.Errorf("please check flag") }

			//读取配置
			viper.SetConfigName(MECONFIG_FILE)
			viper.AddConfigPath(MECONFIG_FILE_PATH)
			err := viper.ReadInConfig()
			if err != nil { return fmt.Errorf("fatal error config file: %s", err) }
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if is_m {
				mode := MODE_value[mode_flag]
				if mode == UNKNOWN_MODE { return fmt.Errorf("unknown mode") }
				err = mode.do()
				if err != nil { return fmt.Errorf("do error: %s", err) }
			}else {
				if is_e {
					err = encode(encode_flag, type_flag)
				}else {
					err = decode(decode_flag, type_flag)
				}
				if err != nil { return fmt.Errorf("convert failed: %s", err) }
			}

			fmt.Println("execute success!")
			return nil
		},
	}
	flags := mecmd.PersistentFlags()
	flags.StringVarP(&mode_flag,   "mode",   "m", FLAG_NOSET, "mode of operation of config")
	flags.StringVarP(&encode_flag, "encode", "e", FLAG_NOSET, "Converts a JSON document to proto")
	flags.StringVarP(&decode_flag, "decode", "d", FLAG_NOSET, "Converts a proto message to JSON")
	flags.StringVarP(&type_flag,   "type",   "t", FLAG_NOSET, "Converts data's type")
	flags.BoolVarP(&is_s,          "save",   "s", false,      "if save artificial config file during operation")

	if mecmd.Execute() != nil {
		os.Exit(1)
	}
}

func f_mode() ([]byte, error) {
	blockdata, err := fetch()
	if err != nil { return nil, err }
	if is_s && viper.GetString("fetch_config.from") == "channel" {
		file := viper.GetString("fetch_config.fetch_file")
		if err = ioutil.WriteFile(file, blockdata, 0644); err != nil {
			return nil, fmt.Errorf("write fetch_file err: %s", err)
		}
	}
	return blockdata, nil
}

func fd_mode() (*cb.Envelope, error) {
	blockdata, err := f_mode()
	if err != nil { return nil, fmt.Errorf("fd_mode f_mode err: %s", err) }
	envelope, err := delta(blockdata)
	if err != nil { return nil, fmt.Errorf("fd_mode delta err: %s", err) }
	data, err := proto.Marshal(envelope)
	if err != nil { return nil, fmt.Errorf("fd_mode marshal err: %s", err) }
	file := viper.GetString("delta_config.delta_file")
	if file == "" {
		return nil, fmt.Errorf("fd_mode err: please set delta_config.delta_file")
	}
	err = ioutil.WriteFile(file, data, 0660)
	if err != nil { return nil, fmt.Errorf("fd_mode write file err: %s", err) }
	return envelope, nil
}

func fds_mode() (*cb.Envelope, error) {
	blockdata, err := f_mode()
	if err != nil { return nil, fmt.Errorf("f_mode err: %s", err) }
	envelope, err := delta(blockdata)
	if is_s {
		file := viper.GetString("delta_config.delta_file")
		if file == "" { return nil, fmt.Errorf("fds_mode err: save is true but delta_config.delta_file is nil") }
		data, err := proto.Marshal(envelope)
		if err != nil { return nil, fmt.Errorf("fds_mode marshal err: %s", err) }
		err = ioutil.WriteFile(file, data, 0660)
		if err != nil { return nil, fmt.Errorf("fds_mode write file err: %s", err) }
	}

	signedenvelope, err := sign(envelope)
	if err != nil { return nil, fmt.Errorf("fds_mode sign err: %s", err) }

	signedenvelopedata, err := proto.Marshal(signedenvelope)
	if err != nil { return nil, fmt.Errorf("marshal signedenvelope error: %s", err) }
	file := viper.GetString("sign_config.sign_file")
	if file == "" { return nil, fmt.Errorf("fds_mode err: please set sign_config.sign_file") }
	err = ioutil.WriteFile(file, signedenvelopedata, 0660)
	if err != nil { return nil, fmt.Errorf("write signedenvelope err: %s", err) }

	return signedenvelope, nil
}

func s_mode() (*cb.Envelope, error) {
	var signedenvelope *cb.Envelope

	if viper.GetString("sign_config.from") == "file" {
		file := viper.GetString("sign_config.sign_file")
		if file == "" { return nil, fmt.Errorf("s_mode err: please set sign_config.sign_file") }
		data, err := ioutil.ReadFile(file)
		if err != nil { return nil, fmt.Errorf("s_mode read file err: %s", err) }

		envelope, err := fprotoutils.UnmarshalEnvelope(data)
		if err != nil { return nil, fmt.Errorf("s_mode unmarshal err: %s", err) }
		signedenvelope, err = sign(envelope)
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

func sc_mode() error {
	signedenvelope, err := s_mode()
	if err != nil { return fmt.Errorf("sc_mode s_mode err: %s", err) }

	return commit(signedenvelope)
}

func c_mode() error {
	if viper.GetString("commit_config.from") == "file" {
		file := viper.GetString("commit_config.commit_file")
		if file == "" { return fmt.Errorf("c_mode err: please set commit_config.commit_file") }
		data, err := ioutil.ReadFile(file)
		if err != nil { return fmt.Errorf("s_mode read file err: %s", err) }
		signedenvelope, err := fprotoutils.UnmarshalEnvelope(data)
		if err != nil { return fmt.Errorf("s_mode unmarshal err: %s", err) }

		return commit(signedenvelope)
	}
	return fmt.Errorf("c_mode err: please set commit_config's from='file' and set commit_file")
}

func fdsc_mode() error {
	blockdata, err := f_mode()
	if err != nil { return fmt.Errorf("fdsc_mode f_mode err: %s", err) }
	envelope, err := delta(blockdata)
	if err != nil { return fmt.Errorf("fdsc_mode delta err: %s", err) }
	if is_s {
		data, err := proto.Marshal(envelope)
		if err != nil { return fmt.Errorf("fdsc_mode marshal err: %s", err) }
		file := viper.GetString("delta_config.delta_file")
		if file == "" { return fmt.Errorf("fdsc_mode err: save is true but delta_config.delta_file is nil") }
		err = ioutil.WriteFile(file, data, 0660)
		if err != nil { return fmt.Errorf("fdsc_mode write file err: %s", err) }
	}

	signedenvelope, err := sign(envelope)
	if err != nil { return fmt.Errorf("fdsc_mode sign err: %s", err) }
	if is_s {
		signedenvelopedata, err := proto.Marshal(signedenvelope)
		if err != nil { return fmt.Errorf("marshal signedenvelope err: %s", err) }
		file := viper.GetString("sign_config.sign_file")
		if file == "" { return fmt.Errorf("fdsc_mode err: save is true but sign_config.sign_file is nil") }
		err = ioutil.WriteFile(file, signedenvelopedata, 0660)
		if err != nil { return fmt.Errorf("write signedenvelope err: %s", err) }
	}

	err = commit(signedenvelope)
	if err != nil { return fmt.Errorf("fdsc_mode commit err: %s", err) }

	return nil
}

func (m *MODE) do() error {
	mode := *m
	var err error

	if mode == F {
		_, err = f_mode()
	}else if mode == FD {
		_, err = fd_mode()
	}else if mode == FDS {
		_, err = fds_mode()
	}else if mode == S {
		_, err = s_mode()
	}else if mode == SC {
		err = sc_mode()
	}else if mode == C {
		err = c_mode()
	}else if mode == FDSC {
		err = fdsc_mode()
	}else {
		return fmt.Errorf("未知操作模式[%d]", mode)
	}

	return err
}

func fetch() ([]byte, error) {
	fmt.Println("start to fetch...")

	var data []byte
	var err error

	if viper.GetString("fetch_config.from") == "channel" {
		fmt.Println("fetch config block from channel...")
		data, err = peerChannelFetchNewestConfigblock()
		if err != nil { return nil, err }
	}else {
		file := viper.GetString("fetch_config.fetch_file")
		fmt.Printf("fetch config block from file [%s]\n", file)
		data, err = ioutil.ReadFile(file)
		if err != nil { return nil, err }
	}

	return data, nil
}

func delta(blockdata []byte) (*cb.Envelope, error) {
	fmt.Println("start to delta...")
	var err error
	if blockdata == nil { return nil, fmt.Errorf("blockdata or conf is nil") }
	//1.找出原有配置信息
	//把配置块Unmarshal成Block，进而分解其中的Envelope（Block.Data.data[0]），该Envelope为一个CONFIG_UPDATE交易
	//分解Envelope中的ConfigEnvelope(Envelope.payload.data)，这里的配置包含了之前的所有配置信息。
	now_config := getConfigFromBlock(blockdata)
	if now_config == nil {
		return nil, fmt.Errorf("get config from configblock error")
	}
	new_config := getConfigFromBlock(blockdata)

	//2.在new_config中更新配置
	err = deltaKvs(new_config)
	if err != nil { return nil, fmt.Errorf("delta kvs err: %s", err) }
	err = deltaOrgs(new_config)
	if err != nil { return nil, fmt.Errorf("delta orgs err: %s", err) }

	//3.形成新的ConfigUpdateEnvelope
	//可以参考Envelope.payload.data.last_update，该结构是一个Envelope，但是一个升级配置的Envelope，
	//其中Envelope.payload.data.last_update.payload.data即为一个ConfigUpdateEnvelope，
	//升级的原始数据即是ConfigUpdateEnvelope.config_update
	//签名为ConfigUpdateEnvelope.signatures
	configupdate, err := fupdate.Compute(now_config, new_config)
	if err != nil {
		return nil, fmt.Errorf("Compute error: %s", err)
	}
	//4.将新的升级配置对象装入信封
	configupdate.ChannelId = viper.GetString("basic_config.channel_id")

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

func sign(envelope *cb.Envelope) (*cb.Envelope, error) {
	fmt.Println("start to sign...")
	if envelope == nil { return nil, fmt.Errorf("args is nil") }
	//1.获取配置信息
	channelid := viper.GetString("basic_config.channel_id")
	local_msp_id := viper.GetString("basic_config.localmsp_id")
	local_msp_path := viper.GetString("basic_config.localmsp_path")
	if channelid == "" || local_msp_id == "" || local_msp_path == "" {
		return nil, fmt.Errorf("channel id or local msp is nil")
	}
	sign_msps := viper.GetStringMapString("sign_config.sign_msps")
	if sign_msps == nil { return nil, fmt.Errorf("msp for sign is nil") }

	var err error
	var signer *mspSigner
	//2.从信封中分解出待签名的升级配置
	payload := &cb.Payload{}
	if err = proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, fmt.Errorf("Unmarshal Payload err: %s", err)
	}
	cue := &cb.ConfigUpdateEnvelope{}
	if err = proto.Unmarshal(payload.Data, cue); err != nil {
		return nil, fmt.Errorf("Unmarshal Payload.Data err: %s", err)
	}
	//3.多个msp对升级配置进行签名
	for mspid, msppath := range sign_msps {
		signer, err = getSigner(mspid, msppath)
		if err != nil { return nil, err }

		sh, err := signer.NewSignatureHeader()
		if err != nil { return nil, err }
		data, err := fprotoutils.Marshal(sh)
		if err != nil { return nil, err }
		cs := &cb.ConfigSignature{ SignatureHeader: data }
		cs.Signature, err = signer.Sign(futil.ConcatenateBytes(cs.SignatureHeader, cue.ConfigUpdate))

		cue.Signatures = append(cue.Signatures, cs)
	}

	//4.使用本地msp组装新的签名信封
	signer, err = getSigner(local_msp_id, local_msp_path)
	if err != nil { return nil, err }
	signedenvelope, err := fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, cue, 0, 0)
	if err != nil { return nil, fmt.Errorf("CreateSignedEnvelope err: %s", err) }

	return signedenvelope, nil
}

func commit(envelope *cb.Envelope) error {
	fmt.Println("start to commit...")
	if envelope == nil { return fmt.Errorf("commit args is nil") }
	//os.Setenv(orderer_address)
	//bc, err = peercommon.GetBroadcastClient()//v1.2，需要设置一些环境变量
	orderer_endpoint := viper.GetString("basic_config.orderer_endpoint")
	orderer_tls_rootcert := viper.GetString("basic_config.orderer_tls_rootcert")
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

//msgName要具体到某个库下的数据类型，该类型经过proto.RegisterType()注册过，在这里的proto.MessageType即可识别
func encode(path, msgname string) error {
	msgtype := proto.MessageType(msgname)
	if msgtype == nil { return fmt.Errorf("message of type %s unknown", msgtype) }
	msg := reflect.New(msgtype.Elem()).Interface().(proto.Message)

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil { return fmt.Errorf("open [%s] err: %s", path, err) }
	err = protolator.DeepUnmarshalJSON(file, msg)
	if err != nil { return fmt.Errorf("error decoding input: %s", err) }

	out, err := proto.Marshal(msg)
	if err != nil { return fmt.Errorf("marshaling err: %s", err) }
	file.Close()

	path = path + ".pb"
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return fmt.Errorf("open [%s] err: %s", path, err) }
	_, err = file.Write(out)
	if err != nil { return fmt.Errorf("writing output[%s] err: %s", path, err) }
	file.Close()

	return nil
}

func decode(path, msgname string) error {
	msgtype := proto.MessageType(msgname)
	if msgtype == nil { return fmt.Errorf("message of type %s unknown", msgtype) }
	msg := reflect.New(msgtype.Elem()).Interface().(proto.Message)

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil { return fmt.Errorf("open [%s] err: %s", path, err) }
	in, err := ioutil.ReadAll(file)
	if err != nil { return fmt.Errorf("reading input err: %s", err) }

	err = proto.Unmarshal(in, msg)
	if err != nil { return fmt.Errorf("unmarshaling err: %s", err) }
	file.Close()

	path = path + ".json"
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return fmt.Errorf("open [%s] err: %s", path, err) }
	err = protolator.DeepMarshalJSON(file, msg)
	if err != nil { return fmt.Errorf("encoding output err: %s", err) }
	file.Close()

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
func peerChannelFetchNewestConfigblock() ([]byte, error) {
	//v1.0 - 至下文建立client对象，v1.2有专门函数建立，不用这样一步一步来
	var opts []grpc.DialOption
	var tls = true//暂时默认tls为true，之后通过配置文件来
	orderer_endpoint := viper.GetString("basic_config.orderer_endpoint")
	if tls {
		orderer_tls_rootcert := viper.GetString("basic_config.orderer_tls_rootcert")
		if orderer_tls_rootcert != "" {
			creds, err := credentials.NewClientTLSFromFile(orderer_tls_rootcert, "")
			if err != nil {
				return nil, fmt.Errorf("Error connecting to %s due to %s", orderer_endpoint, err)
			}
			opts = append(opts, grpc.WithTransportCredentials(creds))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(orderer_endpoint, opts...)
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
	channelid := viper.GetString("basic_config.channel_id")
	local_msp_id := viper.GetString("basic_config.localmsp_id")
	local_msp_path := viper.GetString("basic_config.localmsp_path")
	if channelid == "" || local_msp_id == "" || local_msp_path == "" {
		return nil, fmt.Errorf("channel id or local msp is nil")
	}
	signer, err := getSigner(local_msp_id, local_msp_path)
	if err != nil { return nil, err }
	envelope, err := fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, seekInfo, 0, 0)
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
	envelope, err = fprotoutils.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelid, signer, seekInfo, 0, 0)
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

func getSigner(msp_id, msp_path string) (*mspSigner, error) {
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
		return nil, fmt.Errorf("marshal a SerializedIdentity for %s err: %s", ms.mspid, err)
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

func findAndSetValue(leafkey string, leafjsonvalue interface{}, configvalue *cb.ConfigValue) error {
	if leafkey == "" || leafjsonvalue == nil || configvalue == nil {
		return fmt.Errorf("findAndSetValue args is nil")
	}
	var err error
	var data []byte
	stringvalue, ok := leafjsonvalue.(string)
	if !ok { return fmt.Errorf("value of key-values from delta_kvs should be json string") }

	switch leafkey {
	case fconfig.KafkaBrokersKey:
		brokers := &ab.KafkaBrokers{}
		err = json.Unmarshal([]byte(stringvalue), brokers)
		if err != nil { return err }
		data, err = proto.Marshal(brokers)
		if err != nil { return err }
	case fconfig.BatchSizeKey:
		batchsize := &ab.BatchSize{}
		err = json.Unmarshal([]byte(stringvalue), batchsize)
		if err != nil { return err }
		data, err = proto.Marshal(batchsize)
		if err != nil { return err }
	default:
		return fmt.Errorf("指定配置项修改功能暂未实现")
	}

	configvalue.Value = data
	return nil
}

func deltaKvs(new_config *cb.Config) error {
	if new_config == nil || new_config.ChannelGroup == nil { return fmt.Errorf("new_config is nil") }
	var configgroup *cb.ConfigGroup
	var configgroups map[string]*cb.ConfigGroup
	var configvalues map[string]*cb.ConfigValue
	var configpolicys map[string]*cb.ConfigPolicy
	var mod_policy string
	config_type := -1
	//根据config_path寻找到最终的更新的配置项
	//计算后，configgroup为包含配置值对象的ConfigGroup
	//configgroup中包含工具可能使用到的信息，如连接orderer的tls证书等
	//但是始终都需要使用本地的东西，如签名的私钥，所以干脆都使用本地的，而不使用configgroup中的
	//修改值，只会修改这4类值
	//因此根据返回的config_type判断是否找到最终的配置项
	//例子 path=config.channel_group.groups.Orderer.values.KafkaBrokers.value
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
	kvs := viper.GetStringMap("delta_config.delta_kvs")
	for cp, cv := range kvs {
		//根据配置路径，找到指定的项，
		if !strings.Contains(cp, fixed_prefix) {
			return fmt.Errorf("wrong config path[%s], it's should be %s...", cp, fixed_prefix)
		}
		configpaths = strings.Split(cp, SEPARATOR);
		//最少是3层，如config.channel_group.mod_policy
		if len(configpaths) < 3 {
			return fmt.Errorf("wrong config path[%s], it's fewer than 3", cp)
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
			return fmt.Errorf("config path is wrong, not precise")
		}
		if config_type < 1 || config_type > 3 {
			return fmt.Errorf("after findconfig, wrong config type,it should be 1,2 or 3")
		}

		if config_type == 1 {
			path = configpaths[index+1]
			cp = configpaths[index+2]
			if  cp == ConfigValue_Value {
				//最终要修改Value的值本身value
				configvalue, ok := configvalues[path]
				if !ok { return fmt.Errorf("config[%s] do not exits", path) }
				err := findAndSetValue(path, cv, configvalue)
				if err != nil { return fmt.Errorf("findAndSetValue[%s] err: %s", path, err) }
			}else if cp == ConfigValue_ModPolicy {
				//最终要修改Value的修改策略mod_policy
				configvalues[path].ModPolicy = cv.(string)
			}else {
				return fmt.Errorf("config path is wrong, should end with %s or %s",ConfigValue_ModPolicy, ConfigValue_Value)
			}
		}else if config_type == 2 {
			return fmt.Errorf("no the ability temporarily")
		}else if config_type == 3 {
			return fmt.Errorf("no the ability temporarily")
		}
	}//end for

	return nil
}

func deltaOrgs(new_config *cb.Config) error {
	if new_config == nil || new_config.ChannelGroup == nil { return fmt.Errorf("new_config is nil") }
	ApplicationGroupKey := "Application"
	application_group := new_config.ChannelGroup.Groups[ApplicationGroupKey]
	if application_group == nil || application_group.Groups == nil { return fmt.Errorf("application group in Config is nil") }

	orgs := viper.GetStringMap("delta_config.delta_orgs")
	if len(orgs) == 0 { return fmt.Errorf("there is no org in delta_config.") }

	var org_name, msp_id, msp_path, msp_type string
	var i_policies map[string]interface{}
	var anchors []string
	var data []byte

	MSPKey := "MSP"
	AnchorPeersKey := "AnchorPeers"
	AdminsPolicyKey := "Admins"
	ReadersPolicyKey := "Readers"
	WritersPolicyKey := "Writes"
	SignaturePolicyType := "Signature"
	ImplicitMetaPolicyType := "ImplicitMeta"

	for org_name, _ = range orgs {
		msp_id = viper.GetString(fmt.Sprintf("delta_config.delta_orgs.%s.msp_id", org_name))
		msp_path = viper.GetString(fmt.Sprintf("delta_config.delta_orgs.%s.msp_path", org_name))
		anchors = viper.GetStringSlice(fmt.Sprintf("delta_config.delta_orgs.%s.anchor_peers_enpoint", org_name))
		//>=v1.2存在的配置项
		msp_type = viper.GetString(fmt.Sprintf("delta_config.delta_orgs.%s.msp_type", org_name))
		i_policies = viper.GetStringMap(fmt.Sprintf("delta_config.delta_orgs.%s.policies", org_name))
		fmt.Printf("get org[%s] config: msp_id:%s, msp_path:%s, anchors:%v\n", org_name, msp_id, msp_path, anchors)
		fmt.Printf("get org[%s] config: msp_type:%s, policies:%v\n", org_name, msp_type, i_policies)
		if msp_id == "" || msp_path == "" || anchors == nil || len(anchors) == 0  {
			return fmt.Errorf("org[%s]'s config is invalid, please check.", org_name)
		}

		org_group := cb.NewConfigGroup()
		//1.给org_group添加ConfigValue
		//1.1 msp ConfigValue
		//mspconf, err := msp.GetVerifyingMspConfig(msp_path, msp_id, msp_type)//1.2
		mspconf, err := fmsp.GetVerifyingMspConfig(msp_path, msp_id)
		msp_value := &cb.ConfigValue{}
		msp_value.Value, err = fprotoutils.Marshal(mspconf)
		if err != nil { return fmt.Errorf("org[%s] marshal msp config err: %s", org_name, err) }
		msp_value.ModPolicy = AdminsPolicyKey
		//1.2 anchors ConfigValue
		anchor_value := &cb.ConfigValue{}
		aps := &pb.AnchorPeers{}
		for _, anchor := range anchors {
			endpoint := strings.Split(anchor, ":")
			if len(endpoint) != 2 { return fmt.Errorf("org[%s] can't parse anchor[%s]", org_name, anchor) }
			port, err := strconv.Atoi(endpoint[1])
			if err != nil { return fmt.Errorf("org[%s] can't parse anchor[%s]", org_name, anchor) }
			ap := &pb.AnchorPeer{ Host: endpoint[0], Port: int32(port) }
			aps.AnchorPeers = append(aps.AnchorPeers, ap)
		}
		anchor_value.Value, err = fprotoutils.Marshal(aps)
		if err != nil { return fmt.Errorf("Marshal org[%s] anchors config err: %s", org_name, err) }
		anchor_value.ModPolicy = AdminsPolicyKey

		org_group.Values[MSPKey] = msp_value
		org_group.Values[AnchorPeersKey] = anchor_value
		//2. 给org_group添加Policies
		//如果自定义了策略，则给定自定义策略，若没有，则给默认的策略
		i_policies = viper.GetStringMap(fmt.Sprintf("delta_config.delta_orgs.%s.policies", org_name))
		if len(i_policies) != 0 {
			//>=1.2版本允许自定义策略
			for p_name, _ := range i_policies {
				p_type := viper.GetString(fmt.Sprintf("delta_config.delta_orgs.%s.policies.%s.type", org_name, p_name))
				p_rule := viper.GetString(fmt.Sprintf("delta_config.delta_orgs.%s.policies.%s.rule", org_name, p_name))
				//v1.2中的ImplicitMetaFromString
				if p_type == ImplicitMetaPolicyType {
					rules := strings.Split(p_rule, " ")
					if len(rules) != 2 { return fmt.Errorf("org[%s] implicitmeta policy[%s] invalid", org_name, p_name) }

					imp := &cb.ImplicitMetaPolicy{ SubPolicy: rules[1] }
					switch rules[0] {
					case cb.ImplicitMetaPolicy_ANY.String():
						imp.Rule = cb.ImplicitMetaPolicy_ANY
					case cb.ImplicitMetaPolicy_ALL.String():
						imp.Rule = cb.ImplicitMetaPolicy_ALL
					case cb.ImplicitMetaPolicy_MAJORITY.String():
						imp.Rule = cb.ImplicitMetaPolicy_MAJORITY
					default:
						return fmt.Errorf("org[%s] implicitmeta policy[%s] unknown rule type[%s]", org_name, p_name, rules[0])
					}
					data, err = fprotoutils.Marshal(imp)
					if err != nil { return fmt.Errorf("org[%s] implicitmeta policy[%s] marshal err: %s", org_name, p_name, err) }

					org_group.Policies[p_name] = &cb.ConfigPolicy{
						ModPolicy: AdminsPolicyKey,
						Policy: &cb.Policy{ Type: int32(cb.Policy_IMPLICIT_META), Value: data },
					}
				}else if p_type == SignaturePolicyType {
					sp, err := fcauthdsl.FromString(p_rule)
					if err != nil { return fmt.Errorf("org[%s] signature policy[%s] invalid, err: %s", org_name, p_name, err) }
					data, err = fprotoutils.Marshal(sp)
					if err != nil { return fmt.Errorf("org[%s] signature policy[%s] marshal err: %s", org_name, p_name, err) }
					org_group.Policies[p_name] = &cb.ConfigPolicy{
						ModPolicy: AdminsPolicyKey,
						Policy: &cb.Policy{ Type: int32(cb.Policy_SIGNATURE), Value: data },
					}
				}else {
					return fmt.Errorf("org[%s] policy[%s] type[%s] is unknown", org_name, p_name, p_type)
				}
			}//for end
		}else {
			data, err = fprotoutils.Marshal(fcauthdsl.SignedByMspAdmin(msp_id))
			adminPolicy := &cb.ConfigPolicy{ Policy: &cb.Policy{ Type: int32(cb.Policy_SIGNATURE), Value: data } }
			data, err = fprotoutils.Marshal(fcauthdsl.SignedByMspMember(msp_id))
			memberPolicy := &cb.ConfigPolicy{ Policy: &cb.Policy{ Type: int32(cb.Policy_SIGNATURE), Value: data } }
			if err != nil { return fmt.Errorf("Marshal org[%s] policies err: %s", org_name, err) }

			org_group.Policies[AdminsPolicyKey]  = adminPolicy
			org_group.Policies[ReadersPolicyKey] = memberPolicy
			org_group.Policies[WritersPolicyKey] = memberPolicy
		}
		//3. 给org_group添加ModPolicy
		org_group.ModPolicy = AdminsPolicyKey

		application_group.Groups[org_name] = org_group
	}

	return nil
}

