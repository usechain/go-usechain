// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

package sssa

import (
	"fmt"
	"encoding/json"
	"math/big"
	"crypto/ecdsa"
)

const (
	Thresholdshare = 1
	SubAccountVerifyMsg = 2
)

type Msg struct {
	ID 			uint16 		`json:"ID"`
	MsgType 	uint16 		`json:"MsgType"`
	PointY		string		`json:"Point"`
	Data 		[]PolynomialMsg	`json:"Data"`
}

type PolynomialMsg struct {
	X  	string 				`json:"point_X"`
	Y 	string				`json:"point_Y"`
}

func GetDestNode(port uint16, localID uint16) (uint16, uint16){
	destPort := port + 1
	destID := localID + 1
	if localID == 2 {
		destPort = 9001
		destID = 1
	}
	return destID, destPort
}

func SendPointer(port uint16, id uint16, point_X uint16, point_Y *big.Int, polynomialPubs []ecdsa.PublicKey) {
	var pointdata []PolynomialMsg = make([]PolynomialMsg, len(polynomialPubs))

	fmt.Printf("%x\n", polynomialPubs)
	fmt.Printf("The point is :%x\n", point_Y)

	for i := range polynomialPubs {
		pointdata[i].X = toBase64(polynomialPubs[i].X)
		pointdata[i].Y = toBase64(polynomialPubs[i].Y)
		fmt.Printf("%x,%x\n", fromBase64(pointdata[i].X), fromBase64(pointdata[i].Y))

	}

	msg := 	Msg {
		ID: id,
		MsgType: Thresholdshare,
		PointY: toBase64(point_Y),
		Data: pointdata,
	}
	b, _ := json.Marshal(msg)
	SendMsg(port, b)
}

func SendVerifyMsg(port uint16, id uint16, sharePub *ecdsa.PublicKey) {
	var verifyData []PolynomialMsg = make([]PolynomialMsg, 1)
	verifyData[0].X = toBase64(sharePub.X)
	verifyData[0].Y = toBase64(sharePub.Y)
	fmt.Printf("%x,%x\n", fromBase64(verifyData[0].X) , fromBase64(verifyData[0].Y))

	msg := 	Msg {
		ID: id,
		MsgType: SubAccountVerifyMsg,
		PointY: "",
		Data: verifyData,
	}
	b, _ := json.Marshal(msg)
	SendMsg(port, b)
}

func DistributeMsg(data []byte, serverId uint16,  serverPort uint16) error {
	sharesMsg := &Msg{}
	err := json.Unmarshal(data, &sharesMsg)
	fmt.Printf("%x\n", sharesMsg)
	if err != nil {
		fmt.Println("The msg type error:: ", err)
		return err
	}
	if sharesMsg.MsgType == Thresholdshare {
		fmt.Printf("\n%x, %x\n", fromBase64(sharesMsg.Data[0].X), fromBase64(sharesMsg.Data[0].Y))
		fmt.Printf("\n%x, %x\n", fromBase64(sharesMsg.Data[1].X), fromBase64(sharesMsg.Data[1].Y))

		Checkshares(sharesMsg.Data, sharesMsg.PointY, serverId, sharesMsg.ID)
	}else if sharesMsg.MsgType == SubAccountVerifyMsg {
		HandleSubAccountVerifyRequest(sharesMsg.Data, serverId, sharesMsg.ID, serverPort)
	}
	return nil
}
