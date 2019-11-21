package main

import (
	"LoRaDTUMock/packets"
	"crypto/aes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/brocaar/lorawan"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/rand"
	"syscall"
	"time"
)

func BytesToString(b []byte) string {
	_,err := syscall.UTF16FromString(string(b))
	if err == nil {
		return string(b)
	}
	return ""
}

func newTLSConfig(cafile, certFile, certKeyFile string) (*tls.Config, error) {
	if cafile == "" && certFile == "" && certKeyFile == "" {
		return nil, nil
	}

	tlsConfig := &tls.Config{}

	// Import trusted certificates from CAfile.pem.
	if cafile != "" {
		cacert, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		certpool := x509.NewCertPool()
		certpool.AppendCertsFromPEM(cacert)

		tlsConfig.RootCAs = certpool // RootCAs = certs used to verify server cert.
	}

	// Import certificate and the key
	if certFile != "" && certKeyFile != "" {
		kp, err := tls.LoadX509KeyPair(certFile, certKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{kp}
	}

	return tlsConfig, nil
}

func BuildUpData(gatewayId,devAddr, appSKey,nwkSKey string,
				fCnt uint32,fPort,dr,ch uint8,freq,lsnr float64,
				mType lorawan.MType,fCtrl lorawan.FCtrl,rssi int16,
				userData []byte) (*packets.PushDataPacket,*lorawan.PHYPayload,error) {
	var gatewayMac lorawan.EUI64
	if err := gatewayMac.UnmarshalText([]byte(gatewayId)); err != nil {
		return nil,nil,err
	}
	now := time.Now().Round(time.Second)
	compactTS := packets.CompactTime(now)
	tmms := int64(time.Second / time.Millisecond)

	var phy lorawan.PHYPayload
	phy.MHDR.MType = mType
	phy.MHDR.Major = lorawan.LoRaWANR1
	var mac lorawan.MACPayload
	if err := mac.FHDR.DevAddr.UnmarshalText([]byte(devAddr)); err != nil {
		return nil,nil,err
	}
	mac.FHDR.FCtrl = fCtrl
	mac.FHDR.FCnt = fCnt
	mac.FPort = &fPort
	var dataPayload lorawan.DataPayload
	if err := dataPayload.UnmarshalBinary(true, userData); err != nil {
		return nil,nil,err
	}
	mac.FRMPayload = []lorawan.Payload{&dataPayload}
	phy.MACPayload = &mac
	var aesKey lorawan.AES128Key
	if err := aesKey.UnmarshalText([]byte(appSKey));err != nil {
		return nil,nil,err
	}
	if err := phy.EncryptFRMPayload(aesKey);err != nil {
		return nil,nil,err
	}
	if err := aesKey.UnmarshalText([]byte(nwkSKey));err != nil {
		return nil,nil,err
	}
	sf :=[...]string{"SF12","SF11","SF10","SF9","SF8","SF7"}
	if err := phy.SetUplinkDataMIC(lorawan.LoRaWAN1_0, 0, dr, ch, aesKey, aesKey);err != nil {
		return nil,nil,err
	}
	data,err := phy.MarshalBinary();
	if err != nil {
		return nil,nil,err
	}

	return &packets.PushDataPacket{
		ProtocolVersion: packets.ProtocolVersion2,
		RandomToken:     uint16(rand.Uint32()),
		GatewayMAC:      gatewayMac,
		Payload: packets.PushDataPayload{
			RXPK: []packets.RXPK{
				{
					Time: &compactTS,
					Tmst: 708016819,
					Tmms: &tmms,
					Freq: freq,
					Chan: ch,
					RFCh: 1,
					Stat: 1,
					Modu: "LORA",
					DatR: packets.DatR{LoRa: sf[dr]+"BW125"},
					CodR: "4/5",
					RSSI: rssi,
					LSNR: lsnr,
					Size: uint16(len(data)),
					Data: data,
				},
			},
		},
	},&phy,nil
}


func BuildJoin(gatewayId,appEui,devEui,appKey string,dr,ch uint8,
				freq,lsnr float64,rssi int16,devNonce lorawan.DevNonce) (*packets.PushDataPacket,*lorawan.PHYPayload,error) {
	if dr > 5 || dr < 0 {
		return nil,nil,errors.New("dr exceed limit")
	}
	var gatewayMac lorawan.EUI64
	if err := gatewayMac.UnmarshalText([]byte(gatewayId));err != nil{
		return nil,nil,err
	}
	now := time.Now().Round(time.Second)
	compactTS := packets.CompactTime(now)
	tmms := int64(time.Second / time.Millisecond)

	var phy lorawan.PHYPayload
	phy.MHDR.MType = lorawan.JoinRequest
	phy.MHDR.Major = lorawan.LoRaWANR1
	var DevEUI lorawan.EUI64
	if err := DevEUI.UnmarshalText([]byte(devEui));err != nil{
		return nil,nil,err
	}
	var joinEUI lorawan.EUI64
	if err := joinEUI.UnmarshalText([]byte(appEui));err != nil{
		return nil,nil,err
	}
	phy.MACPayload =  &lorawan.JoinRequestPayload{
		DevEUI:   DevEUI,
		JoinEUI:  joinEUI,
		DevNonce: devNonce,
	}
	var aesKey lorawan.AES128Key
	if err := aesKey.UnmarshalText([]byte(appKey));err != nil{
		return nil,nil,err
	}
	sf :=[...]string{"SF12","SF11","SF10","SF9","SF8","SF7"}
	if err := phy.SetUplinkJoinMIC(aesKey);err != nil{
		return nil,nil,err
	}
	data,err := phy.MarshalBinary()
	if err != nil {
		return nil,nil,err
	}
	return &packets.PushDataPacket{
		ProtocolVersion: packets.ProtocolVersion2,
		RandomToken:     uint16(rand.Uint32()),
		GatewayMAC:      gatewayMac,
		Payload: packets.PushDataPayload{
			RXPK: []packets.RXPK{
				{
					Time: &compactTS,
					Tmst: 708016819,
					Tmms: &tmms,
					Freq: freq,
					Chan: ch,
					RFCh: 1,
					Stat: 1,
					Modu: "LORA",
					DatR: packets.DatR{LoRa: sf[dr]+"BW125"},
					CodR: "4/5",
					RSSI: rssi,
					LSNR: lsnr,
					Size: uint16(len(data)),
					Data: data,
				},
			},
		},
	},&phy,nil
}

// getNwkSKey returns the network session key.
func getNwkSKey(appkey lorawan.AES128Key, netID lorawan.NetID, joinNonce lorawan.JoinNonce, devNonce lorawan.DevNonce) (lorawan.AES128Key, error) {
	return getSKey(0x01, appkey, netID, joinNonce, devNonce)
}

// getAppSKey returns the application session key.
func getAppSKey(appkey lorawan.AES128Key, netID lorawan.NetID, joinNonce lorawan.JoinNonce, devNonce lorawan.DevNonce) (lorawan.AES128Key, error) {
	return getSKey(0x02, appkey, netID, joinNonce, devNonce)
}

func getSKey(typ byte, nwkKey lorawan.AES128Key, netID lorawan.NetID,joinNonce lorawan.JoinNonce, devNonce lorawan.DevNonce) (lorawan.AES128Key, error) {
	var key lorawan.AES128Key
	b := make([]byte, 16)
	b[0] = typ

	netIDB, err := netID.MarshalBinary()
	if err != nil {
		return key, errors.Wrap(err, "marshal binary error")
	}

	joinNonceB, err := joinNonce.MarshalBinary()
	if err != nil {
		return key, errors.Wrap(err, "marshal binary error")
	}

	devNonceB, err := devNonce.MarshalBinary()
	if err != nil {
		return key, errors.Wrap(err, "marshal binary error")
	}

	copy(b[1:4], joinNonceB)
	copy(b[4:7], netIDB)
	copy(b[7:9], devNonceB)

	block, err := aes.NewCipher(nwkKey[:])
	if err != nil {
		return key, err
	}
	if block.BlockSize() != len(b) {
		return key, fmt.Errorf("block-size of %d bytes is expected", len(b))
	}
	block.Encrypt(key[:], b)

	return key, nil
}

func MarshalFRMPayload(p *lorawan.MACPayload) ([]byte, error) {
	var out []byte
	var b []byte
	var err error
	for _, fp := range p.FRMPayload {
		if mac, ok := fp.(*lorawan.MACCommand); ok {
			if p.FPort == nil || (p.FPort != nil && *p.FPort != 0) {
				return []byte{}, errors.New("lorawan: a MAC command is only allowed when FPort=0")
			}
			b, err = mac.MarshalBinary()
		} else {
			b, err = fp.MarshalBinary()
		}
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
