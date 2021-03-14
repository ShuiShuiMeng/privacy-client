package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
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

var baseURL string

// 本地密钥初始化
func initKeys(user *model.User) error {
	// 检查是否有公钥
	keyAPath := filepath.Join(".", "wallet", "keyA.pem")
	keyBPath := filepath.Join(".", "wallet", "keyB.pem")
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
		err := key.Enroll(user, filepath.Join(".", "wallet"))
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
	randKeyPath := filepath.Join(".", "wallet", "randomKey")
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
	priAPath := filepath.Join(".", "wallet", "keyA.pem")
	private, err := key.LoadPriKey(filepath.Clean(priAPath))
	if err != nil {
		return err
	}
	user.PriKeyA = private
	// 加载公钥A
	pubAPath := filepath.Join(".", "wallet", "pub_keyA.pem")
	public, err := key.LoadPubKey(filepath.Clean(pubAPath))
	if err != nil {
		return err
	}
	user.PubKeyA = public
	// 加载私钥b
	priBPath := filepath.Join(".", "wallet", "keyB.pem")
	private, err = key.LoadPriKey(filepath.Clean(priBPath))
	if err != nil {
		return err
	}
	user.PriKeyB = private
	// 加载公钥B
	pubBPath := filepath.Join(".", "wallet", "pub_keyB.pem")
	public, err = key.LoadPubKey(filepath.Clean(pubBPath))
	if err != nil {
		return err
	}
	user.PubKeyB = public
	// 生成公钥地址
	user.Address, err = key.CalcPubAddress(user.PubKeyB.X, user.PubKeyB.Y)
	if err != nil {
		return err
	}
	// 生成共享通道
	user.ShareC, err = key.CalcChannel(user)
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
	CXStr, CYStr, RXStr, RYStr, rStr, err := ecc.Encrypt(user, MX, MY)
	if err != nil {
		return err
	}
	// 数据签名
	sign, err := ecc.Sign(user, CXStr, CYStr)
	if err != nil {
		return err
	}
	// 生成时间戳 纳秒级
	timeStamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	// 封装POST请求参数
	urlValues := url.Values{}
	pubXStr := fmt.Sprintf("%x", user.PubKeyB.X)
	pubYStr := fmt.Sprintf("%x", user.PubKeyB.Y)
	urlValues.Add("pubX", pubXStr)
	urlValues.Add("pubY", pubYStr)
	urlValues.Add("rX", RXStr)
	urlValues.Add("rY", RYStr)
	urlValues.Add("cipX", CXStr)
	urlValues.Add("cipY", CYStr)
	urlValues.Add("time", timeStamp)
	urlValues.Add("sign", sign)
	// 发送FormData的POST请求
	resp, err := http.PostForm(baseURL+"/upload_pri", urlValues)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 解析结果
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body)[0:5] == "10000" {
		key.StoreRandKey(rStr, RXStr, RYStr, user, filepath.Join(".", "wallet", "randomKey"))
		fmt.Println("上传成功")
	} else {
		fmt.Println("上传失败")
	}

	return nil
}

// query 指令
func queryCMD(user *model.User) error {
	params := url.Values{}
	URL, _ := url.Parse(baseURL + "/query_pri")
	params.Set("key", user.Address)
	URL.RawQuery = params.Encode()
	urlPath := URL.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("查询结果：" + string(body))
	return nil
}

// clear 指令
func clearCMD(user *model.User) error {
	fmt.Println("删除旧密钥中...")
	_ = os.Remove("wallet/keyA.pem")
	_ = os.Remove("wallet/keyB.pem")
	_ = os.Remove("wallet/pub_keyA.pem")
	_ = os.Remove("wallet/pub_keyB.pem")
	_ = os.Remove("wallet/randomKey")
	fmt.Println("生成新密钥中...")
	err := key.Enroll(user, filepath.Join(".", "wallet"))
	if err != nil {
		return err
	}
	fmt.Println("新密钥生成完成！")
	return nil
}

// channel指令
func channelCMD(user *model.User) error {
	// 打印aB
	fmt.Println("我的共享通道是：")
	fmt.Printf("X:%x\nY:%x\n", user.ShareC.X, user.ShareC.Y)
	return nil
}

// share指令
func shareCMD(user *model.User) error {
	var pubXstr, pubYstr, scXstr, scYstr string
	fmt.Printf("请输入对方的身份验证公钥：\nPublic Key X:")
	fmt.Scan(&pubXstr)
	fmt.Printf("Public Key Y:")
	fmt.Scan(&pubYstr)
	fmt.Printf("请输入对方的共享通道：\nShare Channel X:")
	fmt.Scan(&scXstr)
	fmt.Printf("Share Channel Y:")
	fmt.Scan(&scYstr)
	sc := &model.ShareChannel{}
	sc.PubX, _ = new(big.Int).SetString(pubXstr, 16)
	sc.PubY, _ = new(big.Int).SetString(pubYstr, 16)
	sc.X, _ = new(big.Int).SetString(scXstr, 16)
	sc.Y, _ = new(big.Int).SetString(scXstr, 16)
	// 生成密钥差值
	// KX, KY, err := key.CalcK(sc, user)
	// 计算一次性地址
	// 打包POST请求
	return nil
}

// get 指令
func getCMD(user *model.User) error {
	var RX, RY string
	fmt.Printf("请输入随机密钥:\nX:")
	fmt.Scan(&RX)
	fmt.Printf("Y:")
	fmt.Scan(&RY)
	// 计算一次性密钥
	PX, PY, err := key.CalcOneKey(RX, RY, user)
	if err != nil {
		return err
	}
	// 生成地址
	add, err := key.CalcPubAddress(PX, PY)
	if err != nil {
		return err
	}
	// 查询
	params := url.Values{}
	URL, _ := url.Parse(baseURL + "/query_pub")
	params.Set("key", add)
	URL.RawQuery = params.Encode()
	urlPath := URL.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("查询结果：" + string(body))

	return nil
}

// 执行指令
func execCMD(cmd string, user *model.User) (err error) {
	switch cmd {
	case "exit": // 退出
		fmt.Println("Bye.")
	case "query": // 查询
		err = queryCMD(user)
	case "upload": // 上传
		err = uploadCMD(user)
	case "clear": // 清空
		err = clearCMD(user)
	case "channel": // 分享共享通道
		err = channelCMD(user)
	case "share":
		//err = shareCMD()
	case "get": // 从公开链查询
		err = getCMD(user)
	default:
		fmt.Printf("Undefined command: %s\n" + cmd)
	}

	return err
}

func main() {
	baseURL = "http://202.120.39.13:51203"
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
		err := execCMD(command, user)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	}
}
