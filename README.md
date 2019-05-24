
## MEConfig Tool

#### 概述

针对区块链项目Hyperledger Fabric项目升级节点配置过于繁琐而编写本工具：ME -> More Easy。

* MEConfig Tool的配置文件为执行目录下的meconfig.json，不可修改配置文件名
* MEConfig Tool依据Hyperledger Fabric更新通道配置的步骤进行编写，主要有：
	1. fetch - 获取通道最新配置块
	2. delta - 修改配置数据，并计算配置增量，将增量配置数据装入Envelope
	3. sign - 根据修改策略对Envelope进行的签名
	4. commit - 向orderer提交配置交易
* 因为fetch/delta/commit这步在整个fabric配置升级的过程中只需执行一次即可，因此MEConfig Tool主要以下功能模式或组合：
	1. fetch。单独获取配置。
	2. delta。根据计算配置增量。
	3. fetch/delta。获取配置并计算增量。
	1. fetch/delta/sign。获取配置，计算增量配置，并签名。
	2. sign。单独对增量配置进行签名。
	3. sign/commit。签名并提交交易。
	4. commit。单独进行提交。

#### config.json释义

* option
	- fetch：是否开启【获取最新config block】的功能，开启为on，关闭为off（下同）
	- delta：是否开启【计算增量配置数据】的功能
	- sign：是否开启【签名配置交易】的功能
	- commit：是否开启【提交配置交易】的功能
	- save：是否开启【保存中间数据】的功能，中间数据有签名信封signed\_envolope.pb、原配置块config\_block.pb
	- depend：commit依赖sign，save依赖fetch/sign，即如果sign=false，即便commit=true，也不会执行commit操作
* basic_info
	- localmsp_xxx：用于fetch或sign，需确保该msp所代表的身份在通道上拥有读权限即可
	- signmsp_xxx：用于sign，若为空，则默认使用localmsp进行签名，若option.sign=off，则无需设置
	- orderer_xxx：用于fetch和commit，若fetch/commit均为off，则无需设置
	- signed_file：用于sign，当fetch=off且sign=on，则说明不是从通道获取配置，而是从该文件中获取配置并追加签名
* config_info
	- 该部分指定要更新的配置项，key为配置路径，value为配置值
	- 配置项路径：将configblock转为json后，从data.data[0].payload.data中的config开始算起，一直到具体要修改的配置项的json路径
	- 配置项值：使用配置项对象的标准的json格式，可参考protos下配置对象结构体中的json tag
	- 如果不修改配置项，则此部分无需设置



