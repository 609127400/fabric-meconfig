
## MEConfig Tool

#### 概述

针对区块链项目Hyperledger Fabric项目升级节点配置过于繁琐而编写本工具：ME -> More Easy。

* MEConfig Tool的配置文件为执行目录下的meconfig.json，不可修改配置文件名
* MEConfig Tool依据Hyperledger Fabric更新通道配置的步骤进行编写，主要有：
	1. fetch - 获取通道最新配置块
	2. delta - 修改配置数据，并计算配置增量，将增量配置数据装入Envelope
	3. sign - 根据修改策略对装有配置数据的Envelope进行的签名
	4. commit - 向orderer提交配置交易Envelope
* 因为fetch/delta/commit这步在整个fabric配置升级的过程中只需执行一次即可，sign可能多次执行，据此特性，MEConfig Tool有以下功能模式组合：
	1. fetch。单独获取配置。
	2. fetch/delta。获取配置并计算增量配置。
	3. fetch/delta/sign。获取配置，计算增量配置，并签名。
	4. sign。单独对增量配置进行签名。
	5. sign/commit。签名并提交交易。
	6. commit。单独进行提交。
	7. fetch/delta/sign/commit。获取配置，计算增量配置，签名增量配置并提交。

#### meconfig.json释义

* basic_info
	- channel_id: 所要更新配置的通道名称 
	- localmsp_xxx：本地用于fetch/commit时向orderer发送Envelope时对Envelope进行签名的msp。确保该msp所代表的身份在通道上拥有写权限即可
	- orderer_xxx：orderer信息。用于fetch和commit时，向orderer提交或获取配置数据
* fetch_config
	- from：值为file，则从config_file指定的配置交易文件进行读取数据。值为channel，则从fabric区块链网络的通道中获取最新配置交易数据。
	- fetch_file：当from值为file时，指定配置交易文件的路径。当save动作开启时，若是从channel中获取最新配置交易数据，该配置交易数据将保存在此文件中。
* delta_config
	- delta_file：当save功能开启时，或不执行后续sign/commit动作时，会将增量配置Envelope保存至此。
	- delta_kvs：指定要更新的配置项，key为【配置项路径】，value为【配置项值】。配置项路径：将configblock转为json后，从data.data[0].payload.data中的config开始算起，一直到具体要修改的配置项的json路径。配置项值：使用配置项对象的标准的json格式，可参考protos下配置对象结构体中的json tag。
	- delta\_orgs：指定要新增的组织。key为【组织名】，value为【组织信息】。【组织信息】中，msp\_id为组织msp的ID；msp\_path为组织msp目录的路径；anchor\_peers\_enpoint为组织锚节点，格式为```["ip1:port1", "ip2:port2"]```。msp\_type为组织msp的类型，只支持bccsp或idemix两类，默认是bccsp；policies为组织msp的策略，key为策略名，value为策略的类型（type）和规则（rule），只有两种类型的策略：（1）type为ImplicitMeta，则rule格式为```ANY/ALL/MAJORITY foo```，foo为策略所指定的组织MSP ID，如```ANY ShareOrgMSP```表示任一ShareOrgMSP的签名即可（2）type为Signature，则rule的格式为AND，OR和admin/member组合而成的规则，如```AND('Org1MSP.member', 'Org2MSP.member'))```表示需要Org1MSP的成员和Org2MSP的成员共同签名。
* sign_config
	- from：值为file，则从signed_file指定的配置交易文件进行读取数据并进行签名。值为fetch，则对从fetch动作获取的Envelope配置交易数据进行签名。
	- sign_file：当from值为file时，指定签名动作要签名的文件的路径。当save动作开启时，签名后的配置交易保存在此文件中。
	- sign_msps：用于签名的msp，key为msp的ID，value为msp的路径。即更新配置或增加新组织，需要哪些组织签名才能生效，需要在这里指定。

#### 命令行flag

对程序的执行效果，主要通过命令行flag进行控制。命令行flag如下：

* `-s`或`--save`：与option.save功能一致，可配合任意命令使用。
* `-m`或`--mode`：指定模式，值为f/fd/fds/s/sc/c/fdsc：
	- `f`：fetch。单独获取配置。
	- `fd`：fetch/delta。获取配置并计算增量配置。
	- `fds`：fetch/delta/sign。获取配置，计算增量配置，并签名。
	- `s`：sign。单独对增量配置进行签名。
	- `sc`：sign/commit。签名并提交交易。
	- `c`：commit。单独进行提交。
	- `fdsc`：fetch/delta/sign/commit。获取配置，计算增量配置，签名增量配置并提交。
* `-e`或`--encode`：将json文件转为程序使用的proto格式文件。同`configtxlator proto_encode`命令。不能与`-m`同时使用。
* `-d`或`--decode`：将proto格式的文件转为可读的json文件。同`configtxlator proto_decode`命令。不能与`-m`同时使用。
* `-t`或`--type`：必须与-e或-d同时使用，指定转换的数据类型。即哪个包下的哪个数据结构，如`common.Block`指common库下的Block结构。同configtxlator中的`--type`。

##### 示例

获取配置，计算增量配置，并签名。同时保存中间生成数据：

`meconfig --mode fds -s`

获取配置，计算增量配置，签名，并提交更新。同时保存中间生成的数据：

`meconfig --mode fdsc -s`

将proto格式的文件./config_block.pb转为同名json格式的文件（将在同目录下生成config_block.json文件）：

`meconfig --decode ./config_block.pb --type common.Block`

将json格式的文件./config_block.json转为同名proto格式的文件（将在同目录下生成config_block.pb文件）：

`meconfig --encode ./config_block.json --type common.Block`


#### 编译

该软件编译比较简单。由于使用了部分hyperledger-fabric源码中的函数和数据结构，因此最好的方式就是放在hyperledger-fabric源码目录中进行编译。如在hyperledger-fabric v1.0源码目录common/tools下执行如下操作：

```git clone https://github.com/609127400/fabric-meconfig.git```

```cd fabric-meconfig```

```go build meconfig.go```

注意：由于引用了部分fabric的源码，且fabric源码的各个版本之间的目录可能存在差异，因此编译该版本时只支持v1.0版本。但在功能上，>=1.0的版本的更新均支持。
