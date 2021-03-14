package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"privacy-client/key"
	"privacy-client/model"
	"strconv"
	"time"
)

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
	KX, KY, RX, RY, r, err := key.CalcK(sc, user)
	if err != nil {
		return err
	}
	// 计算一次性地址
	PX, PY, err := key.CalcOneKey1(r, user)
	if err != nil {
		return err
	}
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
	PX, PY, err := key.CalcOneKey2(RX, RY, user)
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
	params.Set("key", "test")
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

// ExecCMD 执行指令
func ExecCMD(cmd string, user *model.User) (err error) {
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
