
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

* option
	- fetch：是否开启【获取最新config block】的功能，开启为on，关闭为off（下同）
	- delta：是否开启【计算增量配置数据】的功能
	- sign：是否开启【签名配置交易】的功能
	- commit：是否开启【提交配置交易】的功能
	- save：是否开启【保存中间数据】的功能，中间数据只有两个：（1）原配置块config\_block.pb，包含了原有的配置数据。（2）签名信封signed\_envolope.pb，包含了要更新的配置数据和签名。
	- depend：commit依赖sign，save依赖fetch/sign，即如果sign=false，即便commit=true，也不会执行commit操作
* basic_info
	- localmsp_xxx：用于fetch或sign，需确保该msp所代表的身份在通道上拥有读权限即可
	- signmsp_xxx：用于sign，若为空，则默认使用localmsp进行签名，若option.sign=off，则无需设置
	- orderer_xxx：用于fetch和commit，若fetch/commit均为off，则无需设置
* fetch_config
	- from：值为file，则从config_file指定的配置交易文件进行读取数据。值为channel，则从fabric区块链网络的通道中获取最新配置交易数据。
	- fetch_file：当from值为file时，指定配置交易文件的路径。当save动作开启时，若是从channel中获取最新配置交易数据，该配置交易数据将保存在此文件中。
* delta_config
	- delta_file：当save功能开启时，或不执行后续sign/commit动作时，会将增量配置Envelope保存至此。
	- delta_kvs：指定要更新的配置项，key为【配置项路径】，value为【配置项值】。配置项路径：将configblock转为json后，从data.data[0].payload.data中的config开始算起，一直到具体要修改的配置项的json路径。配置项值：使用配置项对象的标准的json格式，可参考protos下配置对象结构体中的json tag。
* sign_config
	- from：值为file，则从signed_file指定的配置交易文件进行读取数据并进行签名。值为fetch，则对从fetch动作获取的Envelope配置交易数据进行签名。
	- sign_file：当from值为file时，指定签名动作要签名的文件的路径。当save动作开启时，签名后的配置交易保存在此文件中。

#### 命令行flag

命令行flag会覆盖meconfig.json中关于option中的功能定义。即，当使用命令行flag时，meconfig.json中的option项的配置将哑掉（其余配置正常工作）。

##### flag

* `-s`或`--save`：与option.save功能一致，可配合任意命令使用。若不设置，则默认使用option.save的值。
* `-m`或`--mode`：指定模式，值为f/fd/fds/s/sc/c/fdsc：
	- `f`：fetch。单独获取配置。
	- `fd`：fetch/delta。获取配置并计算增量配置。
	- `fds`：fetch/delta/sign。获取配置，计算增量配置，并签名。
	- `s`：sign。单独对增量配置进行签名。
	- `sc`：sign/commit。签名并提交交易。
	- `c`：commit。单独进行提交。
	- `fdsc`：fetch/delta/sign/commit。获取配置，计算增量配置，签名增量配置并提交。

##### 示例

获取配置，计算增量配置，并签名。同时保存中间生成数据：

`meconfig --mode fds -s`

#### 编译

该软件编译比较简单。由于使用了部分hyperledger-fabric源码中的函数和数据结构，因此最好的方式就是放在hyperledger-fabric源码目录中进行编译。如在hyperledger-fabric v1.0源码目录common/tools下执行如下操作：

```git clone https://github.com/609127400/fabric-meconfig.git```

```cd fabric-meconfig```

```go build meconfig.go```


