package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"privacy-client/ecc"
	"privacy-client/key"
	"privacy-client/model"
	"strconv"
	"time"
)

var baseURL = "http://202.120.39.13:51203"

// upload 指令
func uploadCMD(user *model.User) error { // 上传数据
	var MX, MY string
	//fmt.Printf("X：")
	//fmt.Scan(&MX)
	//fmt.Printf("Y: ")
	//fmt.Scan(&MY)
	MX = "7d7ceaec3a16205c72922b8b8e6e4e1ec4f9da3c83593cfc40ae64a0f350b5ca" // 测试数据
	MY = "63f2e1082ddc6d754e0d2b7554ea929cebd03a5ee1655e72023b51876aa24441"
	// 数据加密
	CXStr, CYStr, RXStr, RYStr, rStr, err := ecc.Encrypt(user, MX, MY)
	if err != nil {
		return err
	}
	// 数据签名
	sign, err := ecc.Sign(user, CXStr+CYStr)
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
		fmt.Println("上传成功，上传的明文数据为:")
		fmt.Printf("X: %s\n", MX)
		fmt.Printf("Y: %s\n", MY)
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
	_ = os.Remove("wallet/ShareRecords")
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
	sc := &model.ShareChannel{
		AX: user.PubKeyA.X,
		AY: user.PubKeyA.Y,
		BX: user.PubKeyB.X,
		BY: user.PubKeyB.Y,
		X:  user.ShareC.X,
		Y:  user.ShareC.Y,
	}
	scStr, err := sc.ToStr()
	if err != nil {
		return err
	}
	scJSON, err := json.Marshal(scStr)
	if err != nil {
		return err
	}
	fmt.Println("我的共享通道是：")
	fmt.Println(string(scJSON))
	return nil
}

// share指令
func shareCMD(user *model.User) error {
	if user.RandKey == nil || user.RandKey.D == nil {
		fmt.Println("请先上传数据")
		return nil
	}

	var scJSON string
	fmt.Printf("请输入对方的共享通道JSON: ")
	fmt.Scan(&scJSON)
	scStr := &model.ShareChannelStr{}
	err := json.Unmarshal([]byte(scJSON), scStr)
	if err != nil {
		return err
	}
	sc, err := scStr.ToObj()
	if err != nil {
		return err
	}
	// 生成密钥差值
	KX, KY, RX, RY, r, err := key.CalcK(sc, user)
	if err != nil {
		return err
	}
	KXStr := fmt.Sprintf("%x", KX)
	KYStr := fmt.Sprintf("%x", KY)
	RXStr := fmt.Sprintf("%x", RX)
	RYStr := fmt.Sprintf("%x", RY)
	rStr := fmt.Sprintf("%x", r)
	// 计算一次性密钥
	PX, PY, err := key.CalcOneKey1(r, sc)
	if err != nil {
		return err
	}
	PXStr := fmt.Sprintf("%x", PX)
	PYStr := fmt.Sprintf("%x", PY)
	// 计算一次性地址
	oneAdd, err := key.CalcPubAddress(PX, PY)
	if err != nil {
		return err
	}
	// 生成时间戳 纳秒级
	timeStamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	// 生成sender字段
	sender, err := key.CalcSender(timeStamp, user)
	if err != nil {
		return err
	}
	//fmt.Println(sender)
	// 生成签名
	sign, err := ecc.Sign(user, KXStr+KYStr+PXStr+PYStr+sender+timeStamp)
	if err != nil {
		return err
	}
	// 封装POST请求参数
	urlValues := url.Values{}
	selfPubXStr := fmt.Sprintf("%x", user.PubKeyB.X)
	selfPubYStr := fmt.Sprintf("%x", user.PubKeyB.Y)
	urlValues.Add("pubX", selfPubXStr)
	urlValues.Add("pubY", selfPubYStr)
	urlValues.Add("rX", RXStr)
	urlValues.Add("rY", RYStr)
	urlValues.Add("kX", KXStr)
	urlValues.Add("kY", KYStr)
	urlValues.Add("pX", PXStr)
	urlValues.Add("pY", PYStr)
	urlValues.Add("sender", sender)
	urlValues.Add("time", timeStamp)
	urlValues.Add("sign", sign)
	// 发送POST请求
	resp, err := http.PostForm(baseURL+"/share_data", urlValues)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 解析结果
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body)[0:5] == "10000" {
		key.StoreShareRecord(scStr, RXStr, RYStr, rStr, oneAdd, user, filepath.Join(".", "wallet", "ShareRecords"))
		fmt.Println("共享成功，随机公钥JSON为:")
		rkStr := model.RandomKeyStr{RXStr: RXStr, RYStr: RYStr}
		rkJSON, err := json.Marshal(rkStr)
		if err != nil {
			return err
		}
		fmt.Println(string(rkJSON))
	} else {
		fmt.Println("共享失败")
	}
	return nil
}

// get 指令
func getCMD(user *model.User) error {
	var RJSON string
	fmt.Printf("请输入随机密钥JSON: ")
	fmt.Scan(&RJSON)
	rkStr := &model.RandomKeyStr{}
	err := json.Unmarshal([]byte(RJSON), rkStr)
	if err != nil {
		return err
	}
	// 计算一次性密钥
	PX, PY, err := key.CalcOneKey2(rkStr.RXStr, rkStr.RYStr, user)
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
	//params.Set("key", "test")
	URL.RawQuery = params.Encode()
	urlPath := URL.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("查询结果：%s\n", string(body))

	if len(string(body)) == 0 {
		return nil
	}
	pubData := &model.PubDataVO{}
	err = json.Unmarshal(body, pubData)
	if err != nil {
		return err
	}
	MXStr, MYStr, err := ecc.Decrypt(user, pubData.CipherX, pubData.CipherY, pubData.RandomKeyX, pubData.RandomKeyY)
	if err != nil {
		return err
	}
	fmt.Printf("解密后的明文为：\nX: %s\nY: %s\n", MXStr, MYStr)

	return nil
}

func deleteCMD(user *model.User) error {

	var oneAdd string
	fmt.Printf("请输入一次性地址：")
	fmt.Scan(&oneAdd)

	sign, err := ecc.Sign(user, oneAdd)
	if err != nil {
		return err
	}
	// 封装POST请求参数
	urlValues := url.Values{}
	selfPubXStr := fmt.Sprintf("%x", user.PubKeyB.X)
	selfPubYStr := fmt.Sprintf("%x", user.PubKeyB.Y)
	urlValues.Add("BX", selfPubXStr)
	urlValues.Add("BY", selfPubYStr)
	urlValues.Add("add", oneAdd)
	urlValues.Add("sign", sign) // 发送POST请求
	resp, err := http.PostForm(baseURL+"/delete_data", urlValues)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 解析结果
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body)[0:5] == "10000" {
		fmt.Println("删除共享成功")
	} else {
		fmt.Println("删除共享失败")
	}

	return nil
}

func testCMD(user *model.User) error {
	/*addfile, _ := os.OpenFile("adds.txt", os.O_RDONLY, 0666)
	sfile, _ := os.OpenFile("signs.txt", os.O_WRONLY|os.O_APPEND, 0666)
	defer addfile.Close()
	defer sfile.Close()

	writer := bufio.NewWriter(sfile)
	reader := bufio.NewReader(addfile)

	for {
		add, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		add = add[:len(add)-1]
		tmp, _ := ecc.Sign(user, add)

		writer.WriteString(tmp + "\n")
		writer.Flush()
	}*/
	params := url.Values{}
	URL, _ := url.Parse(baseURL + "/test_delete")
	params.Set("add", "GueYJ59CHZMUcSYmDV4ZbVoNSwRg8N27P")
	params.Set("sign", "68712359051111179998841857927774912670242063684864021999939604057500688059844+79921760530000745534193209980515714551791533282790977676996117720435900785400")
	URL.RawQuery = params.Encode()
	urlPath := URL.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("结果：" + string(body))

	return nil 
}

// ExecCMD 执行指令
func ExecCMD(cmd string, user *model.User) (err error) {
	switch cmd {
	case "exit": // 退出
		fmt.Println("Bye.")
		os.Exit(0)
	case "query": // 查询
		err = queryCMD(user)
	case "upload": // 上传
		err = uploadCMD(user)
	case "clear": // 清空
		err = clearCMD(user)
	case "channel": // 分享共享通道
		err = channelCMD(user)
	case "share":
		err = shareCMD(user)
	case "get": // 从公开链查询
		err = getCMD(user)
	case "delete":
		err = deleteCMD(user)
	case "test": // 测试
		testCMD(user)
	default:
		fmt.Printf("Undefined command: %s\n", cmd)
	}

	return err
}
