package main

import (
	"crypto/aes"
	"errors"
	"fmt"
	"github.com/brocaar/lorawan"
	"github.com/bronze1man/radius/internal/radius"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type radiusService struct{}

// getNwkSKey returns the network session key.
func getNwkSKey(appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	return getSKey(0x01, appkey, netID, appNonce, devNonce)
}

// getAppSKey returns the application session key.
func getAppSKey(appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	return getSKey(0x02, appkey, netID, appNonce, devNonce)
}

func getSKey(typ byte, appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	var key lorawan.AES128Key
	b := make([]byte, 0, 16)
	b = append(b, typ)

	// little endian
	for i := len(appNonce) - 1; i >= 0; i-- {
		b = append(b, appNonce[i])
	}
	for i := len(netID) - 1; i >= 0; i-- {
		b = append(b, netID[i])
	}
	for i := len(devNonce) - 1; i >= 0; i-- {
		b = append(b, devNonce[i])
	}
	pad := make([]byte, 7)
	b = append(b, pad...)

	block, err := aes.NewCipher(appkey[:])
	if err != nil {
		return key, err
	}
	if block.BlockSize() != len(b) {
		return key, fmt.Errorf("block-size of %d bytes is expected", len(b))
	}
	block.Encrypt(key[:], b)
	return key, nil
}

func GenerateSessionKeyAttributes(request *radius.Packet, appKey lorawan.AES128Key) (error error, freply radius.LoraRadiusReply) {
	var uplink bool = false

	// verify the MIC of JR
	// UnMarshal the JR to get the devNonce
	// UnMarshal the JA to generate the SessionKeys

	final := radius.LoraRadiusReply{}
	jrR, err := request.GetLoraJoinRequest()
	if err != nil {
		return err, final
	}

	ok, err := jrR.ValidateMIC(appKey)
	if err != nil {
		return fmt.Errorf("validate MIC error: %s", err), final
	}
	if !ok {
		return errors.New("invalid MIC"), final
	}

	jrPayloadR, ok := jrR.MACPayload.(*lorawan.JoinRequestPayload)
	if !ok {
		return errors.New("lorawan: MACPayload should be of type *MACPayload"), final
	}

	jaR, err := request.GetLoraJoinAccept()
	if err != nil {
		return err, final
	}

	dPl, ok := jaR.MACPayload.(*lorawan.DataPayload)
	if !ok {
		return errors.New("lorawan: MACPayload should be of type *MACPayload"), final
	}

	jAPl := &lorawan.JoinAcceptPayload{}
	if err := jAPl.UnmarshalBinary(uplink, dPl.Bytes); err != nil {
		return err, final
	}

	nwkSKey, err := getNwkSKey(appKey, jAPl.NetID, jAPl.AppNonce, jrPayloadR.DevNonce)
	if err != nil {
		return fmt.Errorf("get NwkSKey error: %s", err), final
	}

	nwkSKeyB, err := nwkSKey.MarshalText()
	if err != nil {
		return err, final
	}
	fmt.Println("Network Session Key ", nwkSKey)

	appSKey, err := getAppSKey(appKey, jAPl.NetID, jAPl.AppNonce, jrPayloadR.DevNonce)
	if err != nil {
		return fmt.Errorf("get AppSKey error: %s", err), final
	}

	appSKeyB, err := appSKey.MarshalText()
	if err != nil {
		return err, final
	}
	fmt.Println("Application Session Key ", appSKey)

	phyReplyJA := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: lorawan.JoinAccept,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.JoinAcceptPayload{
			AppNonce: jAPl.AppNonce, // 3 bytes
			NetID:    jAPl.NetID,    // 3 bytes
			DevAddr:  jAPl.DevAddr,  // 4 bytes
		},
	}

	if err = phyReplyJA.SetMIC(appKey); err != nil {
		return fmt.Errorf("set MIC error: %s", err), final
	}

	if err = phyReplyJA.EncryptJoinAcceptPayload(appKey); err != nil {
		return fmt.Errorf("encrypt join-accept error: %s", err), final
	}

	pRJABME, err := phyReplyJA.MarshalBinary()
	if err != nil {
		return err, final
	}

	//jrPayloadRB, err := jrPayloadR.MarshalBinary()
	//if err != nil {
	//	return err, final
	//}
	final = radius.LoraRadiusReply{
		EncryptedJoinAccept: pRJABME,
		//JoinRequest:         jrPayloadRB,
		NwkSKey: nwkSKeyB,
		AppSKey: appSKeyB,
	}
	return nil, final
}

func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	// a pretty print of the request.
	userMap := map[string]string{
		"333738390f6e346d": "2b7e151628aed2a6abf7158809cf4f3c",
		"33313737057e3461": "2b7e151628aed2a6abf7158809cf4f3c",
	}

	fmt.Printf("[Authenticate] %s\n", request.String())
	npac := request.Reply()
	switch request.Code {
	case radius.AccessRequest:
		// get username
		userName := request.GetUsername()
		// check the username in the dictionary and the corresponding appkey.
		if userAppKey := userMap[userName]; userAppKey != "" {
			var appKeyB lorawan.AES128Key
			err := appKeyB.UnmarshalText([]byte(userAppKey))
			if err == nil {
				err, freply := GenerateSessionKeyAttributes(request, appKeyB)
				if err == nil {
					npac.Code = radius.AccessAccept
					npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.UserName, Value: []byte(userName)})
					npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.LoraJoinAccept, Value: freply.EncryptedJoinAccept})
					//npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.LoraJoinRequest, Value: freply.JoinRequest})
					npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.LoraNwkSKey, Value: freply.NwkSKey})
					npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.LoraAppSKey, Value: freply.AppSKey})
					return npac
				}
			}
		}
		npac.Code = radius.AccessReject
		npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
		return npac
	case radius.AccountingRequest:
		// accounting start or end
		npac.Code = radius.AccountingResponse
		return npac
	default:
		npac.Code = radius.AccessAccept
		return npac
	}
}

func main() {
	s := radius.NewServer(":1812", "secret", radiusService{})

	// or you can convert it to a server that accept request
	// from some host with different secret
	cls := radius.NewClientList([]radius.Client{
		radius.NewClient("172.17.0.8", "Acklio"),
	})
	s.WithClientList(cls)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error)
	go func() {
		fmt.Println("waiting for packets...")
		err := s.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()
	select {
	case <-signalChan:
		log.Println("stopping server...")
		s.Stop()
	case err := <-errChan:
		log.Println("[ERR] %v", err.Error())
	}
}
