package ca

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

//Generate a random string of the specified length
func GetRandomString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func TestCAVerify(t *testing.T) {
	//two params is true,and there is only one file.
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	IDKey, err := CAVerify(userID, []string{"./testdata/img1.jpg"})
	if err != nil {
		t.Errorf("error:%v", err)
	} else {
		fmt.Println("two params is true,and there is only one file, so we got register success!")
		fmt.Println("idkey is :", IDKey)
	}

}

func TestCAVerifyIDIsEmpty(t *testing.T) {
	//id is empty but file path is true.
	_, err := CAVerify("", []string{"./testdata/img1.jpg"})
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("userid empty test, error should not be nil")
	}
}
func TestCAVerifyTwoFile(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	//two params is true,more file.
	IDKey, err := CAVerify(userID, []string{"./testdata/img1.jpg", "./testdata/img2.jpg"})
	if err != nil {
		t.Errorf("error:%v", err)
	}
	fmt.Println("IDKey is :", IDKey)
}
func TestCAVerifyParamsIsEmpty(t *testing.T) {
	//file not found
	_, err := CAVerify("", []string{""})
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("two empty params test, error:  %v", err)
	}
}

func TestCAVerifyIfOneFileEmpty(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	_, err := CAVerify(userID, []string{"./testdata/img1.jpg", ""})
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("two empty params test, error should not be nil")
	}
}

func TestCAVerifyPhotoIsEmpty(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	_, err := CAVerify(userID, []string{""})
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("photo path is empty test, error should not be nil")
	}
}

func TestVerifyQuery(t *testing.T) {
	userID := GetRandomString(32)
	fmt.Println("userID: ", userID)
	IDKey, err := CAVerify(userID, []string{"./testdata/img1.jpg", "./testdata/img1.jpg"})
	if err != nil {
		t.Errorf("error:%v", err)
	} else {
		fmt.Println("register success! IDKey is :", IDKey)
	}

	//idkey is exist
	err = VerifyQuery(IDKey)
	if err != nil {
		t.Errorf("error:  %v", err)
	} else {
		fmt.Println("query success.")
	}
}
func TestVerifyQueryIDKeyIsNotExist(t *testing.T) {
	//idkey is not exist
	err := VerifyQuery("71910e1159398046c281c7bba825dedd")
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("idkey is not exist,error should not be nil")
	}
}
func TestVerifyQueryIDIsEmpty(t *testing.T) {
	//test emtpy idkey
	err := VerifyQuery("")
	fmt.Println("err: ", err)
	if err == nil {
		t.Errorf("idkey is empty test, error should not be nil")
	}
}
