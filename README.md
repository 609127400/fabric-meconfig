
## ����

�����������Ŀhyperledger-fabric��Ŀ�ڵ����ñȽ��鷳����д����Ŀ��ME -> More Easy����Ϊ�ͻ��˳���meclient�ͷ������˳���meserver��meserver������fabric�ڵ�������У�meclient�������κ�һ��������ڵ�ͨ�ŵ�������С�meclient�ṩ�������ݺ��������meserver��fabric����ڵ���ͨ����������ִ����Ӧ�������ݺ����


## �������ݣ�

orderer��������

peer��������

ͨ������

��������

kafka����

## ����

#### �ͻ���

##### ����

��Ϊ�ͻ�����ʹ��`github.com/therecipe/qt`��д�������Ҫʹ�øÿ��ṩ�ı��������б��롣������ÿⲢ�����������ϵͳѡ��װqtdeploy�ȳ��򡣰�װ֮�󣬼���ִ�б��빤����

���������fabric-meconfigĿ¼�£�ִ��`qtdeploy -docker --tags nopkcs11`�� --tags nopkcs11����Ϊ���õ���fabric�е�Դ�룬���漰��һ��github.com\miekg\pkcs11\pkcs11.go���ֵ�fatal error:ltdl.h: No such file or directory������Ϊ�ڱ����ʱ����Ҫlibltdl-dev����⣬����qtdeploy�ı�����������Ĭ��û�ð�װ����⡣

#### �����

������Ǳ�׼��go�������ֱ����fabric-meconfig/common/meserverĿ¼�£�ִ��`go build --tags nopkcs11`���ɡ�`--tags nopkcs11`Ҳ����Ϊfatal error:ltdl.h: No such file or directory���󣬵����������ϵͳ�а�װ��libltdl-dev�����Ӵ�tags��ɡ�


## ִ��

1.	��meclient�ļ��У�ִ��fabric-meconfig.sh�ű�������meclient�����ͻ��˽�����򡣿ͻ��˳������־���¼��ͬ�ļ��е�gui.logĿ¼��
2.	���ڲ�����������ڵ��ϣ���meserver�ļ��У�sudo ./meserver��������ԱȨ��ִ��meserver����˳���meserver����־���¼��ͬ�ļ��е�server.log��


## ����

��������һ������֯���������£�

![aaaa.png](./images/aaaa.png "")

1.	A����ѡ��meserver���ڵ��������ַ������Ĭ��ֵ��127.0.0.1����meserver��meclient��ͬһ̨������ϣ�
2.	B����ѡ�����ս���ִ��peer channel update�����������֯�Ľڵ�����
3.	C����Orderer�ڵ��ַ
4.	D����B��ѡ��ڵ������У��ýڵ������У�������Orderer�ڵ��TLS CA֤��·����
5.	E�������Ի�ȡmeserver���ڵĽڵ������е�peer�ڵ������Ļ�����Ϣ�������������������δʵ�֣�

![BBBBBBB.png](./images/BBBBBBB.png "")

1.	A���������ȥ��֯�����֯���
2.	B��������ǩ���ڵ��meserver�ļ�����ַ��127.0.0.1:10000��Ȼ˵��meclient��meserver������ͬһ̨������ϣ�
3.	C����ǩ���ڵ�ִ��ǩ��������ID��������������й���Ա��ɫMSP����Ϊ�����֯��ͨ�����޸Ĳ���Ĭ����MAJORITY��
4.	D����ǩ���ڵ������·������δ�Զ��壬��Ϊ�ռ��ɣ������Զ���ȡǩ���ڵ�FABRIC_CFG_PATH�Ļ�������ֵ��Ϊ����·������·���±������ǩ���ڵ��msp��tls��core.yaml��Ĭ���඼��FABRIC_CFG_PATH��Ŀ¼�£���
5.	E���������������һ��ǩ���ڵ����Ϣ��ͬ����ͨ���޸Ĳ���Ĭ����MAJORITY������Ҫ����Ĺ���Ա�ڵ�ǩ��ʱ������˴����ӡ�
6.	��дҪ��ӵ���֯����Ϣ��
7.	F������д��Ϻ󣬵��Ӧ�á�
8.	G��������ӳɹ�������ʾ��ͼ��Ϣ��





## ���ƣ�

���������docker��������Ľڵ㣬��������Ҫ��������ǰ�ᣬ������ܳɹ�ִ�У�

* orderer�����а���orderer�ؼ��ʣ��ҷ�orderer����������orderer�ؼ��ʣ�peer�ڵ�����������Ҫ����peer�ؼ��֡�
* ��������Թ���ԱȨ�����С�
* �������ڵ���������ķ�ʽ����Ĳ�����δʵ�֡�
* Ŀǰ֧��hyperleder-fabric v1.0�汾��



