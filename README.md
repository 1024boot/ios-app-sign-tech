# iOS签名原理

# 预备知识

先推广产品：

尼卡应用签名管理工具 : [iOS签名-iOS企业签名工具-尼卡签名管理](https://nikaap.com)

尼卡签名管理使用说明 : https://github.com/1024boot/ios-app-sign-manage

## 传统签名

开始之前，我们先简单聊下，什么是签名？维基百科中是这么定义的：

> **签名**是一种将某人的姓名、昵称，甚至是简单的“X”或其他可以表达其个人风格的标记，用**自身独有**的手写特性亲自描绘或书写出来，**用以证明自己的身份与意图**。
> 

从这个定义中我们可以看出，签名就是用来证明身份的，证明信息来源者的身份，比如一封信件上的署名。那么在网络中，是如何保证信息传输的安全性的呢？

先看一个简单的例子，如图所示：

![Untitled](https://user-images.githubusercontent.com/99250217/195104467-2310c952-570b-4c91-b38d-bcfa29dae349.png)


正常情况下，Alice收到的消息就是从Bob那边发过来的，非常美好。但是Hacker可以从中截获Bob发送的消息，进行篡改，然后再发送给Alice，为了尽量避免这种情况的发送，就可以使用数字签名来解决。

## 数字签名

老规矩，先看维基百科中的定义：

> **数字签名**（英语：**Digital Signature**，又称**公钥数字签名**）是一种功能类似写在纸上的普通签名、但是使用了公钥加密领域的技术，以用于鉴别数字信息的方法。
> 

其中有两个关键点：「类似普通签名」和「公钥加密技术」。

**类似普通签名**，这个上面讲了，就是用来证明身份的，没什么可说的了。

**公钥加密技术**也被称为非对称加密，是密码学的一种算法，它需要两个密钥，一个是公开密钥（Public Key），一个是私有密钥（Private Key）。一般公钥用来加密，私钥用来解密。使用公钥加密明文得到密文之后，只有用相对应的密钥才能解密得到明文。同理，用私钥进行加密的话，也只能用对应的公钥才能解密。

还是刚才的例子，我们看看使用数字签名之后的过程是怎样的：

![Untitled 1](https://user-images.githubusercontent.com/99250217/195104551-24190166-960f-4797-a199-2a5a99862016.png)

1. Bob生成一对密钥，包含公钥和私钥
2. Bob自己保存私钥，公钥公开出去
3. 使用哈希算法对发送的信息计算生成**摘要（digest）**
4. 使用**私钥**对**摘要**加密生成**签名（signature）**
5. 将信息和生成的签名放在一起进行发送
6. Alice收到信息之后，使用**公钥**对签名进行**解密**获得**摘要**
7. 使用同样的哈希算法对消息计算**摘要**
8. **比较**上述两个步骤的**摘要**是否一致，如果一直则证明消息是没有被篡改的，否则就说明被篡改过

可以看出这些步骤中，一个关键点就是公钥，Alice拿到的公钥如果不是Bob生成的公钥呢？

![Untitled 2](https://user-images.githubusercontent.com/99250217/195104643-5318779c-5fcc-4dfd-a0c7-5372b272ec75.png)


这种情况下，Hacker自己也生成了一对密钥，Alice实际拿到的公钥是Hacker的，去使用签名校验的时候发现摘要是相等的，但实际上信息已经被篡改了。为了避免这种情况的发生，就需要使用数字证书。

## 数字证书

数字证书是用来证明公钥拥有者身份的，它是一个文件，里面包含了公钥信息、拥有者的身份信息等等。继续看上面的例子，Alice所使用的公钥，如果是从证书中获取的，就可以先查看证书的拥有者信息，这样就可以保证使用到正确的公钥。但是真的如此吗？

假设说Hacker自己也签发了一个证书，里面包含自己的公钥，但是拥有者的信息是伪造的，伪造成Bob的，那这样的话，还是会出现问题。

因此证书里面还包含一个关键的信息就是发行方，虽然说谁都可以发行一个证书，但是只有权威的机构签发的证书才被大家信任，这种机构被称为**数字证书认证机构**（Certificate Authority，缩写为CA）。

只有CA机构的根证书被内置到客户端里面，客户端才会信任这个CA机构所签发的其他证书，根证书是自签名的。

> 在苹果设备上，可以通过[这个链接]([https://support.apple.com/zh-cn/HT209143](https://support.apple.com/zh-cn/HT209143))查看信任的根证书列表。
> 

CA不会直接使用它们的根证书签发第三方申请的证书。这些根证书太宝贵了，直接使用风险太高。

因此，为了保护根证书，CA通常会颁发所谓的中间证书。也就是CA使用根证书先签发一个中间证书，然后在用这个中间证书去签发其他的证书，这样一来，首先根证书是自信任的，然后由根证书签发的中间证书也是可信任的，由中间证书签发的其他的证书也就自然可信了，这就是**证书信任链。**

这里先大概知道这个概念就可以，后面会有具体的例子展示证书信任链。

# iOS签名的作用

好了，说了那么多，终于到今天的主题了。

![Untitled 3](https://user-images.githubusercontent.com/99250217/195104757-3646d7a4-670f-45b5-9920-09f713f2722b.png)


iOS的应用无法直接安装到设备上，需要先经过签名，然后才可以进行安装，这么做主要有以下两个原因：

**安全**，苹果为了保证iPhone、iPad等苹果设备的安全性，要求所有应用都必须经过签名才可以运行。

**利益**，保证安全的同时，苹果也对应用的分发产生了垄断，所有的应用一般都通过App Store进行分发，上架App Store就需要购买付费开发者账户会员。

# 应用分发的渠道

上面提到应用一般都通过App Store进行分发，那么还有哪些渠道呢？

- **App Store**
    
    即苹果的应用商店，开发者在应用开发完成之后需要提交给苹果进行审核，审核通过后，即可上架App Store。
    
- **Ad-Hoc**
    
    这种方式用于公司内部测试时使用，一个开发者账户最多可以注册100台设备。
    
- **Enterprise**
    
    企业级分发，一些大型企业会有一些内部的专用软件，这种软件不会上架到App Store，同时使用数量远远大于100台设备，因此苹果专门为这种企业用户准备了企业账户，每年299刀，企业账户无法上架App。
    
- **Developer**
    
    开发者分发，这种就是开发者在开发App的时候使用的一种分发方式，这种方式也会有100台设备的限制。
    

以上，这几种方式中，App Store 方式的签名流程最为简单：

![Untitled 4](https://user-images.githubusercontent.com/99250217/195105117-4ee51448-8ee2-434b-bc81-ce15132aff7d.png)

在审核通过后，苹果后台会使用苹果私钥对App进行签名，用户从App Store下载之后，系统会使用设备内置的苹果公钥进行解密验证。这一系列的流程都在苹果的可控范围内，因此这种方式就保证了安全性。

其他三种方式应用的签名过程比较复杂，不过整体都差不多，只是使用了不同的证书类型，接下来，我们看看这三种方式是如何签名的。

# 生成密钥（公钥+私钥）

要想签名，我们需要使用私钥进行签名，因此我们应该先生成一对密钥（公钥+私钥）。这里有好几种方式，比如OpenSSL、钥匙串、Xcode等。不过一般情况下我们使用后两种，在Mac设备上可以很方便的利用钥匙串Ap进行管理和查看。

## 使用钥匙串

![Untitled 5](https://user-images.githubusercontent.com/99250217/195105416-56ad2715-dd9c-459e-8967-7c16ebe4c1b5.png)

钥匙串 - 证书助理 - 从证书颁发机构请求证书…
![Untitled 6](https://user-images.githubusercontent.com/99250217/195105517-d05a343f-f874-41af-bb62-2e3b8d158d9b.png)


然后填写申请者的信息，点击继续，选择合适的位置进行保存。然后在钥匙串App中就可以看到刚才生成的公钥和私钥：

![Untitled 7](https://user-images.githubusercontent.com/99250217/195105623-47208e1d-8730-4305-b753-8cfe2db0beb3.png)

查看你刚选择保存的位置会发现有一个`CertificateSigningRequest.certSigningRequest`文件

![Untitled 8](https://user-images.githubusercontent.com/99250217/195105685-210d79bd-7e36-4b38-8617-d7545bcdd663.png)

这个文件的内容包含了个人信息、公钥以及自签名，可通过OpenSSL进行查看：

```bash
openssl req -in Desktop/ios-sign-article/CertificateSigningRequest.certSigningRequest -text -noout
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: emailAddress=test_cer@gmail.com, CN=test_cer_ban, C=CN
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d3:bc:0d:bd:05:d8:4a:31:8a:67:9a:2d:11:7d:
                    xx:xx:....省略
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
         d0:0b:e2:54:56:9f:ce:cb:bd:46:33:42:1f:a9:85:ae:7a:5d:
         30:14:70:d0:a7:69:4f:d4:d4:be:f4:13:8a:35:55:a9:66:3e:
         xx:xx:....省略
```

## 使用Xcode

![Untitled 9](https://user-images.githubusercontent.com/99250217/195105733-983db5f1-a834-4321-a784-d197bdc0fbda.png)

打开Xcode-Preferences…-Accounts添加账户，然后就是创建证书的流程，当然也就包含了生成密钥，这里就不详细介绍了。

# 申请iOS开发者证书

在创建CSR文件完成之后，就可以在苹果开发者网站申请证书了，这里苹果开发者后台其实就是CA机构。

![Untitled 10](https://user-images.githubusercontent.com/99250217/195105815-b8551df5-9257-480b-9e8a-827ec44a2469.png)

这里就对应了前面提到了不同的分发方式，整体都差不多，下面就以 Developer（仅iOS） 为例，选择  iOS App Development 然后点击 Continue。

![Untitled 11](https://user-images.githubusercontent.com/99250217/195105879-25eb7d19-4091-47ba-a913-75078c4089b0.png)

这里需要上传CSR文件，选择我们刚才生成的CSR文件即可，然后点击 Continue。

![Untitled 12](https://user-images.githubusercontent.com/99250217/195105970-94c655cc-c1bd-4eec-800f-1018282964a8.png)

下载下来，是一个`ios_development.cer`文件，双击进行安装，然后在钥匙串中可以进行查看。

![Untitled 13](https://user-images.githubusercontent.com/99250217/195106030-2ca220b9-3ad8-42bb-9c80-a5e650e87c32.png)


可以看到这个证书会自动的和本地的私钥进行配对。查看证书的信息可以看到，该证书是由 Apple Worldwide Developer Relations Certification Authority 发行的，而这个证书又是由 Apple Root CA 进行发行的，这个就是根证书，由自己发行，内置于操作系统中，这就是我们上门提到的证书信任链。

![开发者证书信任链](https://user-images.githubusercontent.com/99250217/195106097-4fc007fd-ace4-429e-9c77-e76f6cebb2e7.png)

开发者证书信任链

苹果开发者账户对生成的证书有数量限制，因此大的开发团队中，不能每个人都申请一个证书用于开发调试，这时候可以通过导出功能，把证书导出为一个p12文件，分享给团队里面的其他成员，由于导出的p12文件里面还包含私钥信息，所以导出时系统会要求设置一个密码，其他人在使用时，需要输入这个密码。

![Untitled 15](https://user-images.githubusercontent.com/99250217/195106201-e896bbc9-42a9-47c5-ba26-5856451c22d0.png)

> .p12是PKCS#12文件的扩展名，它是保存私钥和证书的组合格式，可以通过 `openssl pkcs12 -in Certificates.p12 -nodes -passin pass:"123456"` 命令进行查看。
> 

```bash
MAC verified OK
Bag Attributes
    friendlyName: iPhone Developer: XXXXX (XXXXX)
    localKeyID: XX XX XX 3A 3C 50 C7 FF 2E XX 30 0D 69 F7 20 80 82 4F 15 10
subject=/UID=X9YGXXXXXV2/CN=iPhone Developer: XXX XXX (XXXXXX)/OU=XXCCXXX/O=XXXXXX Co., Ltd./C=US
issuer=/CN=Apple Worldwide Developer Relations Certification Authority/OU=G3/O=Apple Inc./C=US
-----BEGIN CERTIFICATE-----
MIIFxDCCBKygAwIBAgIQFfXx3amp8ravYv6iM/jaeTANBgkqhkiG9w0BAQsFADB1
MUQwXXXXXXX==
-----END CERTIFICATE-----
Bag Attributes
    friendlyName: test_cer_ban
    localKeyID: 28 XX XX 3A 3C XX C7 FF 2E XX 30 0D 69 F7 20 80 82 4F 15 10
Key Attributes: <No Attributes>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTvA29BdhKMYpn
XXXXXXX
-----END PRIVATE KEY-----
```

# 描述文件

除了开发者证书，应用签名时还需要用到描述文件，而描述文件需要使用证书和App ID来生成。

App ID 可以在开发者网站进行创建。

![Untitled 16](https://user-images.githubusercontent.com/99250217/195106281-5987a148-cdc0-42fa-9212-de7cdcc1b025.png)
![Untitled 17](https://user-images.githubusercontent.com/99250217/195106294-4f6e7623-f0d5-4b55-aa73-be131f37286c.png)

App ID 包含App ID prefix（开发者账户的Team ID）、Bundle ID 和权限列表。Bundle ID 有精确和通配符两种形式，通配符的形式平时开发调试demo时更加方便，不用每次都创建一个新的 App ID，而精确的 App ID 一般用于正式发布的 App。

授权列表（Entitlements）是App允许访问系统权限的一个集合，比如是否允许使用Apple Pay、Apple 登录、HealthKit 等等。这是由于iOS使用了[沙盒（Sandbox）]([https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)) 技术，主要目的还是为了安全，在沙盒机制下，即使App的代码出现了问题，也不会影响到整个系统层面。

![Untitled 18](https://user-images.githubusercontent.com/99250217/195106357-e95f120a-ed6e-4cef-9c9f-d1d01f8288ad.png)

如果App中使用到了某项沙盒限制的功能，但是没有在权限列表中声明的话，可能会导致Crash。

APP ID 创建完成之后，就可以去创建 Profile 文件了。

![Untitled 19](https://user-images.githubusercontent.com/99250217/195106436-ec60f7c8-e0d7-4597-aa31-fc8545f9619a.png)

选择 iOS App Development，然后点击 Continue。

![Untitled 20](https://user-images.githubusercontent.com/99250217/195106511-e2040ac1-40ee-4c06-bcae-7c19c057973d.png)

选择刚才创建的 App ID。

![Untitled 21](https://user-images.githubusercontent.com/99250217/195106573-5c198457-35c0-4875-b8a9-d93e5fe2194d.png)

选择刚才生成的证书。

![Untitled 22](https://user-images.githubusercontent.com/99250217/195106652-db6e6239-82e0-471f-a564-f963ffdab491.png)

选择要支持的设备，然后继续输入名字，生成 & 下载即可。

![Untitled 23](https://user-images.githubusercontent.com/99250217/195106723-88c096c0-3025-4f26-af40-97a4af2c8d57.png)

可以看出 `mobileprovision` 文件包含了证书、App ID、Entitlements和设备列表。这个文件使用了标准的[CMS]([https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax))格式，可以通过 `security cms -D -i  just_for_testing.mobileprovision` 命令查看文件的内容。

```xml
security cms -D -i Desktop/ios-sign-article/just_for_testing.mobileprovision

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>just for testing</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>xxxxxx</string>
	</array>
	<key>CreationDate</key>
	<date>2022-10-04T11:29:00Z</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
	</array>
	<key>IsXcodeManaged</key>
	<false/>
	<key>DeveloperCertificates</key>
	<array>
		<data>MIIFxDxxxxxxxx</data>
	</array>

	<key>DER-Encoded-Profile</key>
	<data>MIINZgYJKoxxxxxxx</data>
			<key>PPQCheck</key>
	<true/>

	<key>Entitlements</key>
	<dict>
				<key>aps-environment</key>
		<string>development</string>

				<key>application-identifier</key>
		<string>xxxx.com.abc.test.demo1</string>

				<key>keychain-access-groups</key>
		<array>
				<string>xxxx.*</string>
				<string>com.apple.token</string>
		</array>
				<key>get-task-allow</key>
		<true/>
				<key>com.apple.developer.team-identifier</key>
		<string>xxxxx</string>

	</dict>
	<key>ExpirationDate</key>
	<date>2023-10-04T11:29:00Z</date>
	<key>Name</key>
	<string>just for testing</string>
	<key>ProvisionedDevices</key>
	<array>
		<string>00008110-001604xxxxxx401E</string>
	</array>
	<key>TeamIdentifier</key>
	<array>
		<string>xxxxx</string>
	</array>
	<key>TeamName</key>
	<string>XXXXXXXXXX Co., Ltd.</string>
	<key>TimeToLive</key>
	<integer>365</integer>
	<key>UUID</key>
	<string>xxxxxx-103b-4e27-aa48-0c3d02077d94</string>
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>
```

# 应用签名

到这里应用签名所需的文件都准备齐了，接下来我们一起看下应用签名的具体过程。

应用签名使用的是`codesign` 命令，使用示例如下：

```bash
codesign --force --sign XXXXXXX --entitlements entitlements.plist xxx.app
```

- `--force`参数简写为`-f`，表示当要签名的应用存在旧的签名时，指定该参数则会替换掉旧签名，如不指定该参数则签名操作会报错。
- `--sign`参数简写为`-s`，后面需要跟证书的标识（identity），可以是证书的sha1值，也可以是证书的全名（需要用引号包裹起来）。
- `--entitlements`参数，后面需要跟entitlements文件路径。上面说到了mobileprovision文件里面包含entitlements内容，因此entitlements可以从mobileprovision里面去提取，提取的命令如下：

```bash
security cms -D -i xxxx.mobileprovision > temp.plist
/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' temp.plist > entitlements.plist
rm temp.plist
```

实际上Xcode在真机调试的时候，已经包含了签名的过程，接下来我使用Xcode创建了一个测试工程进行真机调试，查看运行的过程。

![Untitled 24](https://user-images.githubusercontent.com/99250217/195106887-17192474-0bbb-484f-bdbd-d401fbf30c64.png)

可以看到这里的命令和上面我给的示例有一些不太一样。

- `--entitlements` 参数后面跟的是 `CodeSignDemo.app.xcent` 文件，而不是 xxx.plist
    
    CodeSignDemo.app.xcent 文件本质就是一个plist，使用`file`命令查看结果为 `XML 1.0 document text, ASCII text`，只是没有扩展名，使用文本编辑器打开之后如下所示：
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
    	<key>application-identifier</key>
    	<string>XXXXXX.com.abc.test.CodeSignDemo</string>
    	<key>aps-environment</key>
    	<string>development</string>
    	<key>com.apple.developer.in-app-payments</key>
    	<array/>
    	<key>com.apple.developer.team-identifier</key>
    	<string>XXXXXXXX</string>
    	<key>get-task-allow</key>
    	<true/>
    </dict>
    </plist>
    ```
    
- 多了 `--generate-entitlement-der` 参数
    
    这个是苹果在iOS15之后开启的一个新功能，官方文档地址[在这里]([https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format))，简单来说就是会生成一个DER格式编码的 entitlements 信息，放到签名里面。
    
- 多了 `--timestamp\=none`
    
    这个参数指定为none，表示不使用时间戳服务。
    
    那么，App 在签名之后有哪些变化呢？
    
    ![Untitled 25](https://user-images.githubusercontent.com/99250217/195106974-8e69881b-cad1-4fd8-a3ae-6ae28eaa3069.png)

    通过对比两个Ap包发现，签名之后多了`_CodeSignature`文件夹和 `embedded.mobileprovision`文件以及MachO文件有所增大（从127744增大到148112 bytes）。
    
    其中 `embedded.mobileprovision` 文件就是前面提到的描述文件，只是拷贝到App包里面，这个就很好理解了，主要看下其他两个变化。
    
    **CodeResources**
    
    `_CodeResources`文件夹里面只有一个 `CodeResources`文件，通过`file`命令查看发现这个文件其实就是一个XML文件。
    
    ```bash
    file CodeResources
    CodeResources: XML 1.0 document text, ASCII text
    ```
    
    打开之后，内容如下：
    
    ![Untitled 26](https://user-images.githubusercontent.com/99250217/195107074-c124e526-a5d5-40a4-ac74-8874d7944f99.png)

    `files` 里面保存的是每个文件的哈希值，`rules`里面保存的是了计算哈希值的规则说明。而`files2`和`rules2`是对应的，是`files`和`rules`的升级版，引入了sha256。
    
    CodeResources 文件的作用就是校验 App 包里面的文件是否被篡改过，这就是为什么，App 包里面的文件只要更改，就需要重新签名的原因。
    
    **MachO 文件**
    
    使用 `otool` 命令或者 MachOView 软件查看并对比两个MachO文件就会发现，签名之后的MachO文件多了一个`LC_CODE_SIGNATURE` Load Command。
    
    ![Untitled 27](https://user-images.githubusercontent.com/99250217/195107167-9917364b-2147-4fb5-8b8e-7b1ef7e6e1c0.png)
    
    ![Untitled 28](https://user-images.githubusercontent.com/99250217/195107237-e86cb1bc-b6e4-4d23-b5b2-4e5d5717c1f1.png) 

# 整体流程

到这里整个应用签名的过程就说完了，简单总结下：

![Untitled 29](https://user-images.githubusercontent.com/99250217/195107286-9469de07-1ed9-437f-9e54-2e0fa05bbcfe.png)

1. 在本地Mac上生成一对密钥，称之为Mac公钥、Mac私钥，Mac公钥会包含在CSR文件中，Mac私钥保存在钥匙串中
2. 苹果也会有一对密钥，称之为Apple公钥、Apple私钥，Apple私钥在苹果后台保管，Apple公钥被内置在iOS设备里面
3. 使用CSR文件在苹果开发者网站（CA）申请证书，苹果会使用Apple私钥进行签名，证书申请成功之后，双击可导入到钥匙串中，会自动和私钥进行匹配，如果想和别人分享证书可以在钥匙串中选中该证书进行导出操作，会生成一个p12文件（证书+私钥）
4. 创建App ID，配置相关权限
5. 使用证书、App ID、设备列表生成描述文件（mobileprovision)，描述文件会被Apple私钥签名，保证这个描述文件是可信任的
6. 使用Xcode进行Bundle ID、证书以及描述文件的配置
7. 使用Mac私钥对应用进行签名
8. 应用安装到设备上之后，首先使用Apple公钥验证描述文件
9. 描述文件验证通过之后，获取到里面的证书，然后使用Apple公钥验证证书
10. 最后使用Mac公钥去验证整个应用的签名
