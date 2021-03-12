package main

import (
	"crypto/elliptic"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"privacy-client/ecc"
	"privacy-client/key"
	"privacy-client/model"
	"privacy-client/utils"
	"strconv"
	"time"
)

// 本地密钥初始化
func initKeys(user *model.User) error {
	// 检查是否有公钥
	keyAPath := filepath.Join("..", "wallet", "keyA.pem")
	keyBPath := filepath.Join("..", "wallet", "keyB.pem")
	keyAExist := utils.FileExist(filepath.Clean(keyAPath))
	keyBExist := utils.FileExist(filepath.Clean(keyBPath))
	if keyAExist && keyBExist {
		// 路径存在 加载绑定密钥
		fmt.Println("加载绑定密钥中...")
		err := loadKeys(user)
		if err != nil {
			return err
		}
		fmt.Println("加载密钥成功！")
	} else {
		// 路径不存在 生成user
		fmt.Println("未检测到密钥，生成密钥中...")
		err := key.Enroll(user)
		if err != nil {
			return err
		}
		fmt.Println("密钥生成成功")
	}

	return nil
}

// 随机密钥初始化
func initRandKey(user *model.User) error {
	// 检查是否有randomKey
	randKeyPath := filepath.Join("..", "wallet", "randomKey")
	randKeyExist := utils.FileExist(filepath.Clean(randKeyPath))
	if randKeyExist {
		fmt.Println("加载随机密钥中...")
		err := key.LoadRandKey(user, randKeyPath)
		if err != nil {
			return err
		}
		fmt.Println("加载随机密钥成功")
	} else {
		fmt.Println("未检测到随机密钥，请上传数据")
	}

	return nil
}

// 加载绑定密钥
func loadKeys(user *model.User) error {
	// 加载私钥a
	private, err := key.LoadPriKey("keyA.pem")
	if err != nil {
		return err
	}
	user.PriKeyA = private
	// 加载公钥A
	public, err := key.LoadPubKey("pub_keyA.pem")
	if err != nil {
		return err
	}
	user.PubKeyA = public
	// 加载私钥b
	private, err = key.LoadPriKey("keyB.pem")
	if err != nil {
		return err
	}
	user.PriKeyB = private
	// 加载公钥B
	public, err = key.LoadPubKey("pub_keyB.pem")
	if err != nil {
		return err
	}
	user.PubKeyB = public
	// 生成公钥地址
	user.Address, err = key.CalcPubAddress(user.PubKeyB.X, user.PubKeyB.Y)
	if err != nil {
		return err
	}
	return nil
}

// upload 指令
func uploadCMD(user *model.User) error { // 上传数据
	var MX, MY string
	//fmt.Printf("X：")
	//fmt.Scan(&MX)
	//fmt.Printf("Y: ")
	//fmt.Scan(&MY)
	MX = "7d7ceaec3a16205c72922b8b8e6e4e1ec4f9da3c83593cfc40ae64a0f350b5ca" // 默认数据
	MY = "63f2e1082ddc6d754e0d2b7554ea929cebd03a5ee1655e72023b51876aa24441"
	// 数据加密
	CX, CY, RX, RY, err := ecc.Encrypt(user, MX, MY)
	if err != nil {
		return err
	}
	// 数据签名
	sign, err := ecc.Sign(user, CX, CY)
	if err != nil {
		return err
	}
	// 生成时间戳 纳秒级
	timeStamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	// 封装POST请求参数
	urlValues := url.Values{}
	pubX := fmt.Sprintf("%x", user.PubKeyB.X)
	pubY := fmt.Sprintf("%x", user.PubKeyB.Y)
	urlValues.Add("pubX", pubX)
	urlValues.Add("pubY", pubY)
	urlValues.Add("rX", RX)
	urlValues.Add("rY", RY)
	urlValues.Add("cipX", CX)
	urlValues.Add("cipY", CY)
	urlValues.Add("time", timeStamp)
	urlValues.Add("sign", sign)
	// 发送FormData的POST请求
	resp, err := http.PostForm("http://127.0.0.1:8080/upload_pri", urlValues)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 解析结果
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

	return nil
}

// query 指令
func queryCMD() error {
	return nil
}

func main() {
	// 绑定用户内存
	user := &model.User{}
	// 密钥初始化
	err := initKeys(user)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// 随机密钥初始化
	err = initRandKey(user)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 循环读取指令
	var command string
	for {
		fmt.Printf("CMD> ")
		fmt.Scan(&command)
		if command == "exit" {
			fmt.Println("Bye.")
			return
		} else if command == "upload" {

		} else if command == "data" {
			// 查询数据
			params := url.Values{}
			Url, _ := url.Parse("http://127.0.0.1:8080/query_pri")
			params.Set("key", user1.address)
			Url.RawQuery = params.Encode()
			urlPath := Url.String()
			resp, err := http.Get(urlPath)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Println("查询结果：" + string(body))
		} else if command == "clear" {
			// 清除数据
			fmt.Println("删除旧密钥中...")
			err := os.Remove("keyA.pem")
			err = os.Remove("keyB.pem")
			err = os.Remove("pub_keyA.pem")
			err = os.Remove("pub_keyB.pem")
			err = os.Remove("randomKey")
			fmt.Println("生成新密钥中...")
			user1, err = enroll()
			if err != nil {
				fmt.Printf("%s", err.Error())
				return
			}
			fmt.Println("新密钥生成完成！")
		} else if command == "sharetome" {
			// 打印共享通道aB
			curve := elliptic.P256()
			shareX, shareY := curve.ScalarMult(user1.B.X, user1.B.Y, user1.a.D.Bytes())
			fmt.Println("我的共享通道是：")
			fmt.Printf("X:%x\nY:%x\n", shareX, shareY)
		} else if command == "shareto" {
			// 向其他人share
		} else if command == "getshare" {

		} else {
			fmt.Println("Undefined command: " + command)
		}
	}
	/*
		// 生成加密数据 (16进制字符串)
		cipherX, cipherY := encrypt(&user1)
		fmt.Printf("CX:%s\nCY:%s\n", cipherX, cipherY)

		// 计算地址
		pubAddress, err2 := genAddress(user1.B.X, user1.B.Y)
		if err2 != nil {
			fmt.Printf("genKey error %s", err2.Error())
			return
		}
		fmt.Printf("PublicAddress: %s\n", pubAddress)

		// 打包签名
		cipBytes := packData(cipherX, cipherY)
		sign, err := eccSign(cipBytes, &user1)
		if err != nil {
			fmt.Printf(err.Error())
			return
		}
		fmt.Printf("Sgin: %s\n", string(sign))*/
}
