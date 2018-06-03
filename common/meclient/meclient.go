

package meclient


import (
    "fmt"
    "os"
    "context"
    "errors"
    "log"
    "time"
    "google.golang.org/grpc"
    fprotoscommon "github.com/hyperledger/fabric/protos/common"
    fprotospeer "github.com/hyperledger/fabric/protos/peer"
    "github.com/fabric-meconfig/common/protos"
)

var (
    client_log *os.File
    logger *log.Logger
)

func init(){
    var err error
    client_log, err = os.Create("client.log")
    defer client_log.Close()
    if err != nil {
        log.Fatalln("create client log file error")
    }
    logger = log.New(client_log,"[Info]", log.Llongfile)
    logger.SetPrefix("[MEClient-Debug]")
    logger.SetFlags(log.Lshortfile)
}


var client_connections = make(map[string]*grpc.ClientConn)

func EverythingGiveMeIsJustOK(ip string, env *fprotoscommon.Envelope, timeout time.Duration) (*fprotospeer.Response, error) {
    fmt.Println("start to send...")
    if ip == "" || env == nil {
	err := errors.New("ip or envelop is illegal")
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST), Message: err.Error() }, err
    }

    client, err := establishConn(ip)
    if err != nil {
	return &fprotospeer.Response{ Status: int32(fprotoscommon.Status_BAD_REQUEST), Message: err.Error() }, err
    }

    var ctx context.Context
    var ctx_cancel context.CancelFunc = func(){}
    var res *fprotospeer.Response
    done := make(chan int)

    if timeout <= 0 {
	ctx = context.Background()
    }else {
	ctx, ctx_cancel = context.WithTimeout(context.Background(), timeout)
    }
    defer ctx_cancel()

    topic, _, err := mecommon.GetTopicAndPayloadDataFromEnvelope(env)

    go func() {
	if topic < mecommon.Topic_LINE_BETWEEN_CONFIG_AND_COMMAND {
	    res, err = client.DealConfigurationData(ctx, env)
	}else if topic < mecommon.Topic_LINE_BETWEEN_COMMAND_AND_OTHER {
	    res, err = client.DealConfigurationData(ctx, env)
	}else {
	    res, err = client.IamYou(ctx, env)
	}
	done <- 1
    }()

    if timeout <= 0 {
	<-done
    }else {
	select {
	case <-done:
	    //处理完成
	case <-time.After(timeout):
	    err = fmt.Errorf("处理超时，直接返回")
	}
    }

    if err == nil {
	//若执行成功，则关闭连接，若不成功，则保持连接
	client_connections[ip].Close()
	delete(client_connections,ip)
    }

    return res,err
}

func CloseAllConnection () {
    if len(client_connections) > 0 {
	for ip,conn := range client_connections {
	    conn.Close()
	    delete(client_connections,ip)
	}
    }
}

func establishConn(ip string) (mecommon.MEDealerClient, error) {
    conn, ok := client_connections[ip]
    if !ok {
	var opts []grpc.DialOption
	//TODO:建立安全连接的选项，可参考fabric的代码
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithTimeout(5*time.Second))
	opts = append(opts, grpc.WithBlock())

	var err error
	conn, err = grpc.Dial(ip, opts...)
	if err != nil {
	    return nil, err
	}
	client_connections[ip] = conn
    }

    return mecommon.NewMEDealerClient(conn), nil
}






