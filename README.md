# xeca

#### 介绍
基于openssl与gmssl进行证书csr的生成，与证书的颁发。可生成rsa证书、国密SM2证书。P10的组建、解析、签名。证书数据的组建与使用根证书进行证书颁发。

#### 软件架构
软件架构说明
1.  CSPDoit为RSA csr产生的代码。本人还编写了使用UKEY厂商定制的软件CSP接口进行产生csr，后续再考虑分享。
2.  MakeRSACert为通过根证书颁发证书的代码。证书的用法可在CSPDoit模块中修改，或者本模块中修改。
3.  SKFDoit为SM2 csr产生的代码。本人还编写了使用UKEY厂商定制的GM-0016的国密SKF接口进行产生csr，后续再考虑分享。
4.  MakeSM2Cert为通过根证书颁发证书的代码。证书的用法可在SKFDoit模块中修改，或者本模块中修改。
5.  share为使用开源的openssl与gmssl编译出的静态lib。为VS2015所编译。


#### 安装教程

1.  使用VS2015打开xeca.sln进行编译即可。

#### 使用说明

1.  编译好的文件都在bin文件夹中
2.  data为rsa的根证书
3.  data_sm2为sm2的根证书
4.  keycert为生成的密钥对与pfx证书。
5.  testit.exe运行即可产生RSA与SM2证书各一张。

