package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"privacy-client/ecc"
	"privacy-client/key"
	"privacy-client/model"
	"strconv"
	"time"
)

func test(user *model.User) (string, error) {
	scStr := &model.ShareChannelStr{
		XStr:  "66041744d58742f9b0aada7138d219e3da7c6af7710c06d4fe4326f9f8237d35",
		YStr:  "d79a8d35de1ca8c352afd3499df6322c6a8d32bfe8889c0461bab4305525a2ea",
		AXStr: "bd0ff773809c026116ece948dc415195fa760dad4bb6cb8bae6cd44af2151ae",
		AYStr: "9d6496a7f2fe433aeb6263243403444e568e5e97f395c981227f9dd9e518b60e",
		BXStr: "a1080653d728a5b3af46f9e70288dbd122d820cd2e1c349e6bfe74d584737990",
		BYStr: "eea45a383da82df379261983b9fc163a640bac6d04adcb8fe9b32c18cf1d805f",
	}
	sc, err := scStr.ToObj()
	if err != nil {
		return "", err
	}
	// 生成密钥差值
	KX, KY, RX, RY, r, err := key.CalcK(sc, user)
	if err != nil {
		return "", err
	}
	KXStr := fmt.Sprintf("%x", KX)
	KYStr := fmt.Sprintf("%x", KY)
	RXStr := fmt.Sprintf("%x", RX)
	RYStr := fmt.Sprintf("%x", RY)
	//rStr := fmt.Sprintf("%x", r)
	// 计算一次性密钥
	PX, PY, err := key.CalcOneKey1(r, sc)
	if err != nil {
		return "", err
	}
	PXStr := fmt.Sprintf("%x", PX)
	PYStr := fmt.Sprintf("%x", PY)
	// 计算一次性地址
	oneAdd, err := key.CalcPubAddress(PX, PY)
	if err != nil {
		return "", err
	}
	// 生成时间戳 纳秒级
	timeStamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	// 生成sender字段
	sender, err := key.CalcSender(timeStamp, user)
	if err != nil {
		return "", err
	}
	//fmt.Println(sender)
	// 生成签名
	sign, err := ecc.Sign(user, KXStr+KYStr+PXStr+PYStr+sender+timeStamp)
	if err != nil {
		return "", err
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
		return "", err
	}
	defer resp.Body.Close()
	// 解析结果
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body)[0:5] == "10000" {
		//key.StoreShareRecord(scStr, RXStr, RYStr, rStr, oneAdd, user, filepath.Join(".", "wallet", "ShareRecords"))
		//fmt.Println("共享成功，随机公钥JSON为:")
		//rkStr := model.RandomKeyStr{RXStr: RXStr, RYStr: RYStr}
		//rkJSON, err := json.Marshal(rkStr)
		//if err != nil {
		//	return "", err
		//}
		//fmt.Println(string(rkJSON))
	} else {
		fmt.Println("共享失败")
	}
	return oneAdd, nil
}

func testmain(user *model.User) error {
	file, err := os.OpenFile("adds.txt", os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	var oneAdd string
	for i := 0; i < 1000; i++ {
		oneAdd, err = test(user)
		fmt.Printf("%d:%s\n", i, oneAdd)
		writer.WriteString(oneAdd + "\n")
		writer.Flush()
	}

	return nil
}
