
//csshare - client server share
//用于存放客户端和服务端都能用到的一些数据类型、常量

package csshare


//server发给client的字符串若需要分隔，则以此为分隔符
var SEPARATOR string = "|_|"


//保存通道的详细信息 - 客户端点击获取通道详细信息时，返回的数据为此
type ChannelInfo struct {
    ChannelID string `label:"频道ID:"`
    CreateTime string `label:"创建时间:"`
    Creator string `label:"创建者:"`
    CreatorMspID string `label:"创建者MSPID:"`
    CreatorSignatrue string `label:"创建者签名:"`
    //组织信息 - key为组织名，value(map[string]interface{})为信息或配置
    OrgsInfo map[string]map[string]interface{} `label:"组织配置:"`
    //把策略的原始字符串发给客户端，在客户端处理
    Policies map[string]string `label:"通道策略:"`
    Config map[string]interface{} `label:"通道配置:"`
}

//以下结构体均来自于fabric源码，为顺利获取label值，有稍微改动

type AnchorPeer struct {
	Host string `protobuf:"bytes,1,opt,name=host" json:"host,omitempty"`
	Port int32 `protobuf:"varint,2,opt,name=port" json:"port,omitempty"`
}

//作为配置项锚点存储在map里面的key
const CV_AP string = "cv_ap"
type AnchorPeers struct {
	AnchorPeers []*AnchorPeer `protobuf:"bytes,1,rep,name=anchor_peers,json=anchorPeers" json:"anchor_peers,omitempty"`
}

//配置值MSP在map里的key
const CV_MSP string = "cv_msp"
type KeyInfo struct {
	KeyIdentifier string `protobuf:"bytes,1,opt,name=key_identifier,json=keyIdentifier" json:"key_identifier,omitempty"`
	KeyMaterial string `protobuf:"bytes,2,opt,name=key_material,json=keyMaterial,proto3" json:"key_material,omitempty"`
}

type SigningIdentityInfo struct {
	PublicSigner string `protobuf:"bytes,1,opt,name=public_signer,json=publicSigner,proto3" json:"public_signer,omitempty"`
	PrivateSigner *KeyInfo `protobuf:"bytes,2,opt,name=private_signer,json=privateSigner" json:"private_signer,omitempty"`
}

type FabricOUIdentifier struct {
	Certificate string `protobuf:"bytes,1,opt,name=certificate,proto3" json:"certificate,omitempty"`
	OrganizationalUnitIdentifier string `protobuf:"bytes,2,opt,name=organizational_unit_identifier,json=organizationalUnitIdentifier" json:"organizational_unit_identifier,omitempty"`
}

type FabricCryptoConfig struct {
	SignatureHashFamily string `protobuf:"bytes,1,opt,name=signature_hash_family,json=signatureHashFamily" json:"signature_hash_family,omitempty"`
	IdentityIdentifierHashFunction string `protobuf:"bytes,2,opt,name=identity_identifier_hash_function,json=identityIdentifierHashFunction" json:"identity_identifier_hash_function,omitempty"`
}

type FabricMSPConfig struct {
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	RootCerts []string `protobuf:"bytes,2,rep,name=root_certs,json=rootCerts,proto3" json:"root_certs,omitempty"`
	IntermediateCerts []string `protobuf:"bytes,3,rep,name=intermediate_certs,json=intermediateCerts,proto3" json:"intermediate_certs,omitempty"`
	Admins []string `protobuf:"bytes,4,rep,name=admins,proto3" json:"admins,omitempty"`
	RevocationList []string `protobuf:"bytes,5,rep,name=revocation_list,json=revocationList,proto3" json:"revocation_list,omitempty"`
	SigningIdentity *SigningIdentityInfo `protobuf:"bytes,6,opt,name=signing_identity,json=signingIdentity" json:"signing_identity,omitempty"`
	OrganizationalUnitIdentifiers []*FabricOUIdentifier `protobuf:"bytes,7,rep,name=organizational_unit_identifiers,json=organizationalUnitIdentifiers" json:"organizational_unit_identifiers,omitempty"`
	CryptoConfig *FabricCryptoConfig `protobuf:"bytes,8,opt,name=crypto_config,json=cryptoConfig" json:"crypto_config,omitempty"`
	TlsRootCerts []string `protobuf:"bytes,9,rep,name=tls_root_certs,json=tlsRootCerts,proto3" json:"tls_root_certs,omitempty"`
	TlsIntermediateCerts []string `protobuf:"bytes,10,rep,name=tls_intermediate_certs,json=tlsIntermediateCerts,proto3" json:"tls_intermediate_certs,omitempty"`
}

type MSPConfig struct {
	Type int32 `protobuf:"varint,1,opt,name=type" json:"type,omitempty"`
	Config *FabricMSPConfig `protobuf:"bytes,2,opt,name=config,proto3" json:"config,omitempty"`
}

type ConfigValue struct {
	Version   string `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	Value     interface{} `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	ModPolicy string `protobuf:"bytes,3,opt,name=mod_policy,json=modPolicy" json:"mod_policy,omitempty"`
}

//策略类型
type Policy_PolicyType int32

const (
	Policy_UNKNOWN       Policy_PolicyType = 0
	Policy_SIGNATURE     Policy_PolicyType = 1
	Policy_MSP           Policy_PolicyType = 2
	Policy_IMPLICIT_META Policy_PolicyType = 3
)

/*
//策略1 对应类型1
type SignaturePolicyEnvelope struct {
	Version    int32                   `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	Rule       *SignaturePolicy        `protobuf:"bytes,2,opt,name=rule" json:"rule,omitempty"`//签名策略
	Identities []*MSPPrincipal `protobuf:"bytes,3,rep,name=identities" json:"identities,omitempty"`//身份集合
}

//MSPPrincipal
type MSPPrincipal struct {
	//ROLE、ORGANIZATION_UNIT、IDENTITY
	PrincipalClassification string `protobuf:"varint,1,opt,name=principal_classification,json=principalClassification,enum=common.MSPPrincipal_Classification" json:"principal_classification,omitempty"`
	Principal interface{} `protobuf:"bytes,2,opt,name=principal,proto3" json:"principal,omitempty"`
}

//ROLE
type MSPRole struct {
	MspIdentifier string `protobuf:"bytes,1,opt,name=msp_identifier,json=mspIdentifier" json:"msp_identifier,omitempty"`
	//MEMBER、ADMIN
	Role string `protobuf:"varint,2,opt,name=role,enum=common.MSPRole_MSPRoleType" json:"role,omitempty"`
}

//ORGANIZATION_UNIT
type OrganizationUnit struct {
	MspIdentifier string `protobuf:"bytes,1,opt,name=msp_identifier,json=mspIdentifier" json:"msp_identifier,omitempty"`
	OrganizationalUnitIdentifier string `protobuf:"bytes,2,opt,name=organizational_unit_identifier,json=organizationalUnitIdentifier" json:"organizational_unit_identifier,omitempty"`
	//哈希值
	CertifiersIdentifier string `protobuf:"bytes,3,opt,name=certifiers_identifier,json=certifiersIdentifier,proto3" json:"certifiers_identifier,omitempty"`
}

//IDENTITY
//fabric源码msp/identities.go下实现

//SignaturePolicy
type isSignaturePolicy_Type interface {
	isSignaturePolicy_Type()
}

type SignaturePolicy_SignedBy struct {
	SignedBy int32 `protobuf:"varint,1,opt,name=signed_by,json=signedBy,oneof"`
}
type SignaturePolicy_NOutOf_ struct {
	NOutOf *SignaturePolicy_NOutOf `protobuf:"bytes,2,opt,name=n_out_of,json=nOutOf,oneof"`
}

type SignaturePolicy_NOutOf struct {
	N     int32              `protobuf:"varint,1,opt,name=n" json:"n,omitempty"`
	Rules []*SignaturePolicy `protobuf:"bytes,2,rep,name=rules" json:"rules,omitempty"`
}

func (*SignaturePolicy_SignedBy) isSignaturePolicy_Type() {}
func (*SignaturePolicy_NOutOf_) isSignaturePolicy_Type()  {}

type SignaturePolicy struct {
	Type isSignaturePolicy_Type `protobuf_oneof:"Type"`
}

//策略3 对应类型3
type ImplicitMetaPolicy struct {
	SubPolicy string  `protobuf:"bytes,1,opt,name=sub_policy,json=subPolicy" json:"sub_policy,omitempty"`
	Rule      string `protobuf:"varint,2,opt,name=rule,enum=common.ImplicitMetaPolicy_Rule" json:"rule,omitempty"`
}

type Policy struct {
	Type  int32  `protobuf:"varint,1,opt,name=type" json:"type,omitempty"`
	Value interface{} `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}
*/

//联盟
const CV_CST string = "cv_cst"
type Consortium struct {
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

//orderer节点地址
const CV_OADDR string = "cv_oaddr"
type OrdererAddresses struct {
	Addresses []string `protobuf:"bytes,1,rep,name=addresses" json:"addresses,omitempty"`
}


//----------------------------------------------
//AddOrg信息
const (
    AddOrgSignNode string = "a"
    AddOrgSignNodeNum string = "b"
    AddOrgOrgName string = "c"
    AddOrgConfigtx string = "d"
    AddOrgCrypto string = "e"
    AddOrgContainerID string = "f"
    AddOrgOrdererIP string = "g"
    AddOrgChannelID string = "h"
    AddOrgTLSCAPath string = "i"
)
