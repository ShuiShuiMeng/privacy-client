package main

import (
	"fmt"
	"path/filepath"
	"privacy-client/cmd"
	"privacy-client/key"
	"privacy-client/model"
	"privacy-client/utils"
)

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
		err := cmd.ExecCMD(command, user)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	}
}
