
package meclient


import (
    "fmt"
    "context"
    "bytes"
    "testing"
    "google.golang.org/grpc"
    "github.com/stretchr/testify/assert"
    "github.com/spf13/viper"
    pcommon "github.com/fabric-meconfig/common/protos"
)

func getExampleConfigurationData(t *testing.T) []byte {
     data1 := []byte(`
General:
    LedgerType: s
    ListenAddress: s
    ListenPort: s
    TLS:
        Enabled: s
        PrivateKey: s
        Certificate: s
        RootCAs:
	- s
	- s
	- s
        ClientAuthEnabled: s
        ClientRootCAs:
	- s
    LogLevel: s
    GenesisMethod: s
    GenesisProfile: s
    GenesisFile: s
    LocalMSPDir: s
    LocalMSPID: s
    Profile:
        Enabled: s
        Address: s
    BCCSP:
        Default: s
        SW:
            Hash: s
            Security: s
            FileKeyStore:
                KeyStore: s
`)
    data2 := []byte(`
FileLedger:
    Location: s
    Prefix: s
`)
    data3 := []byte(`
Kafka:
    Retry:
        ShortInterval: ds
        ShortTotal: dm
        LongInterval: dm
        LongTotal: dh
        NetworkTimeouts:
            DialTimeout: ds
            ReadTimeout: ds
            WriteTimeout: ds
        Metadata:
            RetryBackoff: dms
            RetryMax: d
        Producer:
            RetryBackoff: dms
            RetryMax: d
        Consumer:
            RetryBackoff: ds
    Verbose: s
    TLS:
      Enabled: s
      PrivateKey:
        File: s
      Certificate:
        File: s
      RootCAs:
        File: s
    Version: s
`)

    all := make([][]byte, 3)
    all[0] = data1
    all[1] = data2
    all[2] = data3

    return bytes.Join(all, []byte(""))
}

func TestSendConfigurationData(t *testing.T) {
    port := 10000
    ip := "0.0.0.0"

    addr := fmt.Sprintf("%s:%d", ip, port)

    var opts []grpc.DialOption
    //TODO:建立安全连接的选项，可参考fabric的代码
    opts = append(opts, grpc.WithInsecure())
    conn, err := grpc.Dial(addr, opts...)
    defer conn.Close()
    assert.Equal(t,err,nil)

    client := pcommon.NewMEDealerClient(conn)

    config := getExampleConfigurationData(t)

    env := &pcommon.Envelope{
	Payload: pcommon.MarshalOrPanic(
	    &pcommon.Payload{
		Header: &pcommon.Header{
		    ChannelHeader: pcommon.MarshalOrPanic(&pcommon.ChannelHeader{ Type:pcommon.HeaderType_ORDERER_CONFIG }),
		    SignatureHeader: nil},
		Data: config }),
	Signature: nil }
    var res *pcommon.Response
    res, err = client.DealConfigurationData(context.Background(), env)
    assert.Equal(t,err,nil)
    assert.NotEqual(t,res,nil)
}

func TestWriteConfiguration(t *testing.T) {
    v := viper.New()
    v.AddConfigPath("./")
    v.SetConfigType("yaml")

    data := getExampleConfigurationData(t)
    err := v.ReadConfig(bytes.NewBuffer(data))
    assert.NotEqual(t, err, nil)

    err = v.WriteConfigAs("orderer.yaml")
    assert.NotEqual(t, err, nil)
}
