### 使用介绍
本项目基于SpringBoot开发，使用Maven和MySQL，支持RSA、ECDSA、SM2签名算法的证书生成及签发。

默认使用SpringCloud nacos注册中心，如需更改详见启动配置文件。

源码参考：https://governance-doc.readthedocs.io/zh_CN/latest/docs/WeBankBlockchain-Governance-Cert/index.html

### 数据库

**cert_info**

	pk_id
	cert_content        #证书内容
	is_ca_cert			#证书是否可往下签发
	issuer_cn			#同一个体系内的根证书的 cert_info.issuer_cn
	issuer_key_id		#同一个体系内的根证书的 cert_keys_info.pk_id
	issuer_org			#同一个体系内的根证书的 cert_info.issuer_org
	parent_cert_id		#上级证书的 pk_id
	serial_number		#自动生成
	subject_cn			#commonName
	subject_key_id		#私钥id,对应私钥的 cert_keys_info.pk_id
	subject_org			#organizationName
	subject_pub_key		#公钥
	user_id				#

**cert_keys_info**

	pk_id
	key_alg     #密钥算法
	key_pem     #私钥 pem 格式字符串
	user_id		#

**cert_request_info**

	pk_id
	cert_request_content
	issue				#默认 false，签发完变 true
	parent_cert_id		#上级证书的 pk_id
	parent_cert_user_id	#上级证书的 user_id
	subject_cn          #子证书的 commonName
	subject_key_id		#子证书的 cert_keys_info.pk_id
	subject_org         #子证书的 organizationName
	user_id				#子证书的 user_id


### 启动
微服务部署注册spring cloud，pom.xml 中 jackson 相关包需要注意以下改动，如 spring-boot.version = 2.3.4.RELEASE

```xml
<groupId>com.fasterxml.jackson.core</groupId>
<artifactId>jackson-databind</artifactId>
<version>2.10.5</version>

<groupId>com.fasterxml.jackson.core</groupId>
<artifactId>jackson-annotations</artifactId>
<version>2.9.6</version>
```

