

package mecommon

import (
    "fmt"
    "github.com/golang/protobuf/proto"
    "github.com/hyperledger/fabric/protos/common"
)

func MarshalOrPanic(m proto.Message) []byte {
    data, err := proto.Marshal(m)
    if err != nil {
	panic(err)
    }
    return data
}

func Marshal(m proto.Message) ([]byte, error) {
    return proto.Marshal(m)
}

func GetTopicAndPayloadDataFromEnvelope(env *common.Envelope) (Topic, []byte, error) {
    payload := &common.Payload{}
    err := proto.Unmarshal(env.Payload, payload)
    if err != nil {
	return Topic_PEER_CONFIG, nil, fmt.Errorf("Unmarshal Payload error")
    }
    ch := &common.ChannelHeader{}
    err = proto.Unmarshal(payload.Header.ChannelHeader, ch)
    if err != nil {
	return Topic_FOO, nil, fmt.Errorf("Unmarshal ChannelHeader error")
    }

    return Topic(ch.Type), payload.Data, nil
}

//TODO:增加签名
func GetSendEnvelope(data []byte, topic Topic) *common.Envelope {
    return &common.Envelope{
	Payload: MarshalOrPanic(
	    &common.Payload{
		Header: &common.Header{
		    ChannelHeader: MarshalOrPanic(&common.ChannelHeader{ Type: int32(topic) }),
		    SignatureHeader: nil},
		Data: data }),
	Signature: nil }
}

func TopicIsConfig(t int) bool {
    //topicComboBox.AddItems([]string{"PEER_CONFIG","PEER_COMMAND","ORDERER_CONFIG","ORDERER_CHANNEL_CONFIG","ORDERER_COMMAND"})
    return (t == 0 || t == 2 || t == 3)
}
