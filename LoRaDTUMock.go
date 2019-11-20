package main

import (
	"LoRaDTUMock/model"
	"LoRaDTUMock/packets"
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/brocaar/loraserver/api/gw"
	"github.com/brocaar/lorawan"
	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang/protobuf/proto"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/rand"
	"os"
	"syscall"
	"time"
)

type ConnectConfig struct {
	Host string `json:"host"`
	Port int `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	CACert string	`json:"ca_cert"`
	TLSCert string	`json:"tls_cert"`
	TLSKey string `json:"tls_key"`
}

type DTUConfig struct {
	OTAA      bool 		`json:"otaa"`
	GatewayId string	`json:"gatewayId"`
	DevEui    string	`json:"devEui"`
	DevAddr   string	`json:"devAddr"`
	AppKey    string	`json:"appKey"`
	AppSKey   string	`json:"appSKey"`
	NwkSKey   string	`json:"nwkSKey"`
	FPort     uint8		`json:"fPort"`
	FCnt      uint32	`json:"fCnt"`
	Freq      float64	`json:"freq"`
	msg       []byte
	devNonce  lorawan.DevNonce
}

type DTUMainWindow struct {
	*walk.MainWindow
	mqttClient 							paho.Client
	upModel                             *model.DTUUpModel
	downModel                           *model.DTUDownModel
	upTv,downTv                         *walk.TableView
	host,username,password 				*walk.LineEdit
	port             					*walk.NumberEdit
	connect, disconnect,caConf,send     *walk.PushButton
	msg                            		*walk.TextEdit
	ssl               					*walk.CheckBox
	connConf                            ConnectConfig
	dtuConf 							DTUConfig
	connConfFileName 					string
	dtuConfFileName						string
}
func BytesToString(b []byte) string {
	_,err := syscall.UTF16FromString(string(b))
	if err == nil {
		return string(b)
	}
	return ""
}
func main() {
	mw := &DTUMainWindow{upModel: model.NewDTUUpModel(),downModel:model.NewDTUDownModel()}
	maxWidth := int(win.GetSystemMetrics(win.SM_CXSCREEN)) - 200
	maxHeight := int(win.GetSystemMetrics(win.SM_CYSCREEN)) - 100
	err := MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "LoRaDTUMock",
		//Icon:		"test.ico",
		Size:     Size{maxWidth,maxHeight },
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					Label{Text:"主机/IP:"},
					LineEdit{AssignTo:&mw.host},
					Label{Text:"端口:"},
					NumberEdit{AssignTo:&mw.port,MinSize:Size{Width:50}},
					Label{Text:"用户名:"},
					LineEdit{AssignTo:&mw.username},
					Label{Text:"密码:"},
					LineEdit{AssignTo:&mw.password,PasswordMode:true},
					PushButton{Text:"连接", AssignTo: &mw.connect,OnClicked:mw.Connect},
					PushButton{Text:"断开连接", AssignTo:&mw.disconnect, Enabled:false, OnClicked: mw.Disconnect},
					CheckBox{Text:"开启SSL/TLS",AssignTo:&mw.ssl,OnClicked:mw.SSL},
					PushButton{Text:"证书配置",Enabled:false,AssignTo:&mw.caConf,OnClicked: mw.ConnectConfig},
					PushButton{Text:"终端配置",OnClicked: mw.DTUConfig},
					PushButton{Text:"发送",AssignTo:&mw.send,OnClicked: mw.Send},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					TableView{
						AssignTo:         &mw.upTv,
						CheckBoxes:       true,
						ColumnsOrderable: true,
						MultiSelection:   true,
						Columns: []TableViewColumn{
							{Title: "序号"},
							{Title: "终端EUI"},
							{Title: "网关ID"},
							{Title: "信号强度"},
							{Title: "信噪比"},
							{Title: "频率"},
							{Title: "计数"},
							{Title: "端口"},
							{Title: "HEX数据"},
							{Title: "ASCII数据"},
							{Title: "时间"},
						},
						Model: mw.upModel,
						OnItemActivated: mw.upTvItemActivated,
					},
					TableView{
						AssignTo:         &mw.downTv,
						CheckBoxes:       true,
						ColumnsOrderable: true,
						MultiSelection:   true,
						Columns: []TableViewColumn{
							{Title: "序号"},
							{Title: "终端EUI"},
							{Title: "网关ID"},
							{Title: "频率"},
							{Title: "计数"},
							{Title: "端口"},
							{Title: "HEX数据"},
							{Title: "ASCII数据"},
							{Title: "时间"},
						},
						Model:  mw.downModel,
						OnItemActivated: mw.downTvItemActivated,
					},
				},
			},
		},
	}.Create()
	if err != nil {
		panic("LoRaDTUMock窗口创建失败")
	}
	_ = mw.port.SetValue(1883)
	dir,_ := os.Getwd()
	mw.connConfFileName = dir + "/LoRaDTUMock.json"
	mw.dtuConfFileName = dir + "/LoRaDTUConf.json"
	data, err := ioutil.ReadFile(mw.connConfFileName)
	if err == nil {
		err = json.Unmarshal(data, &mw.connConf)
		if err != nil {
			msg := "配置文件格式错误:" + err.Error()
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			return
		}
		_ = mw.host.SetText(mw.connConf.Host)
		_ = mw.port.SetValue(float64(mw.connConf.Port))
		_ = mw.username.SetText(mw.connConf.Username)
		_ = mw.password.SetText(mw.connConf.Password)
	}
	mw.Run()
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

func (mw *DTUMainWindow) Connect()  {
	go func() {
		if mw.host.Text() != "" && mw.port.Value() > 0 {
			opts := paho.NewClientOptions()
			serverAddr := fmt.Sprintf("%s:%d",mw.host.Text(),int(mw.port.Value()))
			if mw.ssl.Checked() {
				if mw.connConf.CACert != "" {
					serverAddr = fmt.Sprintf("ssl://%s:%d",mw.host.Text(),int(mw.port.Value()))
					tlsconfig, err := newTLSConfig(mw.connConf.CACert, mw.connConf.TLSCert, mw.connConf.TLSKey)
					if err != nil {
						msg := "证书加载错误:" + err.Error()
						walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
					}
					if tlsconfig != nil {
						opts.SetTLSConfig(tlsconfig)
					}
				}else{
					msg := "证书未配置,服务端单向认证只需配置CA证书,双向认证还需配置客户端证书及秘钥"
					walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
					return
				}
			}
			opts.AddBroker(serverAddr)
			opts.SetUsername(mw.username.Text())
			opts.SetPassword(mw.password.Text())
			opts.SetConnectTimeout(5 * time.Second)
			mw.mqttClient = paho.NewClient(opts)
			token := mw.mqttClient.Connect()
			if token.Wait() && token.Error() == nil {
				mw.connConf.Host = mw.host.Text()
				mw.connConf.Port = int(mw.port.Value())
				mw.connConf.Username = mw.username.Text()
				mw.connConf.Password = mw.password.Text()
				var confData bytes.Buffer
				d,_  := json.Marshal(&mw.connConf)
				_ = json.Indent(&confData, d, "", "\t")
				_ = ioutil.WriteFile(mw.connConfFileName,confData.Bytes(),0644)
				mw.host.SetEnabled(false)
				mw.port.SetEnabled(false)
				mw.username.SetEnabled(false)
				mw.password.SetEnabled(false)
				mw.disconnect.SetEnabled(true)
				mw.connect.SetEnabled(false)
				mw.caConf.SetEnabled(false)
				topic := "gateway/+/command/#"
				token := mw.mqttClient.Subscribe(topic,0, mw.HandleData)
				if token.Wait() && token.Error() != nil {
					msg := "订阅失败:" + token.Error().Error()
					walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
				}
			}else{
				msg := "连接失败:" + token.Error().Error()
				walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			}
		}else{
			msg := "主机/IP不能为空，端口不能为0"
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
		}
	}()
}

func (mw *DTUMainWindow) Disconnect()  {
	mw.connect.SetEnabled(true)
	mw.host.SetEnabled(true)
	mw.port.SetEnabled(true)
	mw.username.SetEnabled(true)
	mw.password.SetEnabled(true)
	mw.disconnect.SetEnabled(false)
	mw.caConf.SetEnabled(true)
	mw.mqttClient.Disconnect(0)
}

func (mw *DTUMainWindow) DTUConfig()  {
	var dlg *walk.Dialog
	var otaa *walk.CheckBox
	var gatewayId,devEUI,devAddr,appKey,appSKey,nwkSKey *walk.LineEdit
	var fPort,fCnt,freq *walk.NumberEdit
	var msg *walk.TextEdit
	var acceptPB, cancelPB *walk.PushButton
	_ = Dialog{
		Title: "DTU配置",
		Layout:   VBox{},
		AssignTo: &dlg,
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize: Size{400, 200},
		Children: []Widget{
			Composite{
				Layout:Grid{Columns: 2},
				Children:[]Widget{
					Label{Text:"入网方式:"},
					CheckBox{AssignTo: &otaa,Text:"OTAA入网",OnClicked: func() {
						if otaa.Checked() {
							appKey.SetEnabled(true)
							devAddr.SetEnabled(false)
							appSKey.SetEnabled(false)
							nwkSKey.SetEnabled(false)
						}else{
							appKey.SetEnabled(false)
							devAddr.SetEnabled(true)
							appSKey.SetEnabled(true)
							nwkSKey.SetEnabled(true)
						}
					}},
					Label{Text:"网关ID:"},
					LineEdit{AssignTo:&gatewayId},
					Label{Text:"终端EUI:"},
					LineEdit{AssignTo:&devEUI},
					Label{Text:"终端地址:"},
					LineEdit{AssignTo:&devAddr},
					Label{Text:"应用秘钥:"},
					LineEdit{AssignTo:&appKey,Enabled:false},
					Label{Text:"应用会话秘钥:"},
					LineEdit{AssignTo:&appSKey},
					Label{Text:"网络会话秘钥:"},
					LineEdit{AssignTo:&nwkSKey},
					Label{Text:"端口:"},
					NumberEdit{AssignTo:&fPort},
					Label{Text:"计数:"},
					NumberEdit{AssignTo:&fCnt},
					Label{Text:"频率:"},
					NumberEdit{AssignTo:&freq,Decimals:2},
					Label{Text:"消息:"},
					TextEdit{AssignTo:&msg},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &acceptPB,
						Text:     "确定",
						OnClicked: func() {
							mw.dtuConf.OTAA = otaa.Checked()
							mw.dtuConf.GatewayId = gatewayId.Text()
							mw.dtuConf.DevEui = devEUI.Text()
							mw.dtuConf.DevAddr = devAddr.Text()
							mw.dtuConf.AppKey = appKey.Text()
							mw.dtuConf.AppSKey = appSKey.Text()
							mw.dtuConf.NwkSKey = nwkSKey.Text()
							mw.dtuConf.FPort = uint8(fPort.Value())
							mw.dtuConf.FCnt = uint32(fCnt.Value())
							mw.dtuConf.Freq = freq.Value()
							mw.dtuConf.msg = []byte(msg.Text())

							var confData bytes.Buffer
							d,_  := json.Marshal(&mw.dtuConf)
							_ = json.Indent(&confData, d, "", "\t")
							_ = ioutil.WriteFile(mw.dtuConfFileName,confData.Bytes(),0644)
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "取消",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Create(mw)
	data, err := ioutil.ReadFile(mw.dtuConfFileName)
	if err == nil {
		err = json.Unmarshal(data, &mw.dtuConf)
		if err != nil {
			msg := "配置文件格式错误:" + err.Error()
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			return
		}
	}
	otaa.SetChecked(mw.dtuConf.OTAA)
	_ = gatewayId.SetText(mw.dtuConf.GatewayId)
	_ = devEUI.SetText(mw.dtuConf.DevEui)
	_ = devAddr.SetText(mw.dtuConf.DevAddr)
	_ = appKey.SetText(mw.dtuConf.AppKey)
	_ = appSKey.SetText(mw.dtuConf.AppSKey)
	_ = nwkSKey.SetText(mw.dtuConf.NwkSKey)
	_ = fPort.SetValue(float64(mw.dtuConf.FPort))
	_ = fCnt.SetValue(float64(mw.dtuConf.FCnt))
	_ = freq.SetValue(mw.dtuConf.Freq)
	_ = msg.SetText(string(mw.dtuConf.msg))

	dlg.Run()
}
func (mw *DTUMainWindow) SSL()  {
	if mw.ssl.Checked() {
		mw.caConf.SetEnabled(true)
	}else{
		mw.caConf.SetEnabled(false)
	}
}

func (mw *DTUMainWindow) ConnectConfig()  {
	var dlg *walk.Dialog
	var caCert,tlsCert,tlsKey *walk.LineEdit
	var acceptPB, cancelPB *walk.PushButton
	_ = Dialog{
		Title: "连接配置",
		Layout:   VBox{},
		AssignTo: &dlg,
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize: Size{400, 200},
		Children: []Widget{
			Composite{
				Layout:Grid{Columns: 3},
				Children:[]Widget{
					Label{Text:"CA证书:"},
					LineEdit{Text:Bind("CACert"),AssignTo:&caCert},
					PushButton{Text:"打开",OnClicked: func() {
						dlg := new(walk.FileDialog)
						dlg.Title = "请选择CA证书"
						dlg.Filter = "CA证书 (*.crt)|*.crt|所有文件 (*.*)|*.*"
						if ok, err := dlg.ShowOpen(mw); err != nil {
							return
						} else if !ok {
							return
						}
						_ = caCert.SetText(dlg.FilePath)
					}},
					Label{Text:"客户端证书:"},
					LineEdit{Text:Bind("TLSCert"),AssignTo:&tlsCert},
					PushButton{Text:"打开",OnClicked: func() {
						dlg := new(walk.FileDialog)
						dlg.Title = "请选择客户端证书"
						dlg.Filter = "客户端证书 (*.crt)|*.crt|所有文件 (*.*)|*.*"
						if ok, err := dlg.ShowOpen(mw); err != nil {
							return
						} else if !ok {
							return
						}
						_ = tlsCert.SetText(dlg.FilePath)
					}},
					Label{Text:"客户端证书秘钥:"},
					LineEdit{Text:Bind("TLSKey"),AssignTo:&tlsKey},
					PushButton{Text:"打开",OnClicked: func() {
						dlg := new(walk.FileDialog)
						dlg.Title = "请选择客户端证书秘钥"
						dlg.Filter = "客户端证书秘钥 (*.key)|*.key|所有文件 (*.*)|*.*"
						if ok, err := dlg.ShowOpen(mw); err != nil {
							return
						} else if !ok {
							return
						}
						_ = tlsKey.SetText(dlg.FilePath)
					}},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &acceptPB,
						Text:     "确定",
						OnClicked: func() {
							mw.connConf.CACert = caCert.Text()
							mw.connConf.TLSCert = tlsCert.Text()
							mw.connConf.TLSKey = tlsKey.Text()
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "取消",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Create(mw)
	_ = caCert.SetText(mw.connConf.CACert)
	_ = tlsCert.SetText(mw.connConf.TLSCert)
	_ = tlsKey.SetText(mw.connConf.TLSKey)
	dlg.Run()
}

func (mw *DTUMainWindow) BuildUpData() (*packets.PushDataPacket,*lorawan.PHYPayload) {
	now := time.Now().Round(time.Second)
	compactTS := packets.CompactTime(now)
	tmms := int64(time.Second / time.Millisecond)

	var phy lorawan.PHYPayload
	phy.MHDR.MType = lorawan.ConfirmedDataUp
	phy.MHDR.Major = lorawan.LoRaWANR1
	var mac lorawan.MACPayload
	_ = mac.FHDR.DevAddr.UnmarshalText([]byte(mw.dtuConf.DevAddr))
	_ = mac.FHDR.FCtrl.UnmarshalBinary([]byte{128})
	mac.FHDR.FCnt = mw.dtuConf.FCnt
	mac.FPort = &mw.dtuConf.FPort
	var dataPayload lorawan.DataPayload
	_ = dataPayload.UnmarshalBinary(true, mw.dtuConf.msg)
	mac.FRMPayload = []lorawan.Payload{&dataPayload}
	phy.MACPayload = &mac
	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(mw.dtuConf.NwkSKey))
	_ = phy.EncryptFRMPayload(aseKey)
	sf :=[...]string{"SF12","SF11","SF10","SF9","SF8","SF7"}
	var dr uint8 = 5
	var ch uint8 = 2
	_ = phy.SetUplinkDataMIC(lorawan.LoRaWAN1_0, 0, dr, ch, aseKey, aseKey)
	data,_ := phy.MarshalBinary()
	var gatewayMac lorawan.EUI64
	_ = gatewayMac.UnmarshalText([]byte(mw.dtuConf.GatewayId))
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
					Freq: mw.dtuConf.Freq,
					Chan: ch,
					RFCh: 1,
					Stat: 1,
					Modu: "LORA",
					DatR: packets.DatR{LoRa: sf[dr]+"BW125"},
					CodR: "4/5",
					RSSI: -51,
					LSNR: 7,
					Size: uint16(len(data)),
					Data: data,
				},
			},
		},
	},&phy
}

func (mw *DTUMainWindow) BuildJoin() (*packets.PushDataPacket,*lorawan.PHYPayload) {
	now := time.Now().Round(time.Second)
	compactTS := packets.CompactTime(now)
	tmms := int64(time.Second / time.Millisecond)
	var phy lorawan.PHYPayload
	phy.MHDR.MType = lorawan.JoinRequest
	phy.MHDR.Major = lorawan.LoRaWANR1
	var DevEUI lorawan.EUI64
	_ = DevEUI.UnmarshalText([]byte(mw.dtuConf.DevEui))
	mw.dtuConf.devNonce = lorawan.DevNonce(rand.Uint32())
	phy.MACPayload =  &lorawan.JoinRequestPayload{
		DevEUI:   DevEUI,
		JoinEUI:  lorawan.EUI64{8, 7, 6, 5, 4, 3, 2, 1},
		DevNonce: mw.dtuConf.devNonce,
	}
	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(mw.dtuConf.AppKey))
	sf :=[...]string{"SF12","SF11","SF10","SF9","SF8","SF7"}
	var dr uint8 = 5
	var ch uint8 = 2
	_ = phy.SetUplinkJoinMIC(aseKey)
	data,_ := phy.MarshalBinary()
	var gatewayMac lorawan.EUI64
	_ = gatewayMac.UnmarshalText([]byte(mw.dtuConf.GatewayId))
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
					Freq: mw.dtuConf.Freq,
					Chan: ch,
					RFCh: 1,
					Stat: 1,
					Modu: "LORA",
					DatR: packets.DatR{LoRa: sf[dr]+"BW125"},
					CodR: "4/5",
					RSSI: -51,
					LSNR: 7,
					Size: uint16(len(data)),
					Data: data,
				},
			},
		},
	},&phy
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

func (mw *DTUMainWindow) HandleData(client paho.Client, message paho.Message){
	var downlinkFrame gw.DownlinkFrame
	err := proto.Unmarshal(message.Payload(),&downlinkFrame)
	if err == nil {
		packet,err := packets.GetPullRespPacket(packets.ProtocolVersion2, uint16(rand.Uint32()),downlinkFrame)
		if err == nil{
			var phy lorawan.PHYPayload
			err = phy.UnmarshalBinary(packet.Payload.TXPK.Data)
			if err == nil {
				switch phy.MHDR.MType {
				case lorawan.JoinAccept:
					mw.HandleJoinAccept(&phy)
				case lorawan.ConfirmedDataDown,lorawan.UnconfirmedDataDown:
					mw.HandleDataDown(&phy)
				default:
					fmt.Println("未处理的帧")
				}
				var origData bytes.Buffer
				jsonData,_ := phy.MarshalJSON()
				_ = json.Indent(&origData, jsonData, "", "  ")
				dd := &model.DTUDown{
					Index: mw.downModel.Len() + 1,
					DevEUI: mw.dtuConf.DevEui,
					DevAddr: mw.dtuConf.DevAddr,
					GatewayID: hex.EncodeToString(downlinkFrame.TxInfo.GatewayId),
					Time:time.Now().Format("2006-01-02 15:04:05"),
					OrigData:origData.String(),
				}
				if phy.MHDR.MType == lorawan.ConfirmedDataDown ||  phy.MHDR.MType == lorawan.UnconfirmedDataDown {
					mpl := phy.MACPayload.(*lorawan.MACPayload)
					if mpl.FPort != nil {
						dd.FPort = *mpl.FPort
					}
					dd.FCnt = mpl.FHDR.FCnt
					p,err := MarshalFRMPayload(mpl)
					if err == nil {
						dd.AsciiData = BytesToString(p)
						dd.HexData = hex.EncodeToString(p)
					}
				}
				mw.downModel.Items = append(mw.downModel.Items, dd)
				mw.downModel.PublishRowsReset()
				_ = mw.downTv.SetSelectedIndexes([]int{})
			}
		}
	}
}

func (mw *DTUMainWindow) HandleJoinAccept(phy *lorawan.PHYPayload){
	key := mw.dtuConf.AppKey
	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(key))
	err := phy.DecryptJoinAcceptPayload(aseKey)
	if err != nil {
		fmt.Println(err)
	}
	jap,ok := phy.MACPayload.(*lorawan.JoinAcceptPayload)
	if !ok {
		fmt.Println("lorawan: MACPayload must be of type *JoinAcceptPayload")
	}
	mw.dtuConf.DevAddr = jap.DevAddr.String()
	dn := mw.dtuConf.devNonce
	appSKey,err := getAppSKey(aseKey,jap.HomeNetID,jap.JoinNonce,dn)
	if err == nil {
		mw.dtuConf.AppSKey = appSKey.String()
		fmt.Println(mw.dtuConf.AppSKey)
	}
	nwkSKey,err := getNwkSKey(aseKey,jap.HomeNetID,jap.JoinNonce,dn)
	if err == nil {
		mw.dtuConf.NwkSKey = nwkSKey.String()
		fmt.Println(mw.dtuConf.NwkSKey)
	}
}

func (mw *DTUMainWindow) HandleDataDown(phy *lorawan.PHYPayload){
	key := mw.dtuConf.NwkSKey
	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(key))
	err := phy.DecryptFRMPayload(aseKey)
	if err == nil {
		mpl := phy.MACPayload.(*lorawan.MACPayload)
		mw.dtuConf.DevAddr = mpl.FHDR.DevAddr.String()
	}
}

func (mw *DTUMainWindow) PushData(gatewayEUI string,event string, msg proto.Message)  {
	topic := fmt.Sprintf("gateway/%s/event/%s",gatewayEUI,event)
	b, err := proto.Marshal(msg)
	if err != nil {
		fmt.Println("marshal message error")
	}

	if token := mw.mqttClient.Publish(topic, 0, false, b); token.Wait() && token.Error() == nil {
		fmt.Println("mqtt message ok")
	}else{
		fmt.Println("mqtt message error")
	}
}

func (mw *DTUMainWindow) Send(){
	if mw.dtuConf.OTAA && mw.dtuConf.DevAddr == ""{
		packet,phy := mw.BuildJoin()
		var origData bytes.Buffer
		jsonData,_ := phy.MarshalJSON()
		_ = json.Indent(&origData, jsonData, "", "  ")
		du := &model.DTUUp{
			Index:mw.upModel.Len() + 1,
			DevEUI:mw.dtuConf.DevEui,
			MType:phy.MHDR.MType.String(),
			GatewayID:mw.dtuConf.GatewayId,
			Rssi:packet.Payload.RXPK[0].RSSI,
			LoRaSNR:packet.Payload.RXPK[0].LSNR,
			Frequency:packet.Payload.RXPK[0].Freq,
			Time:time.Now().Format("2006-01-02 15:04:05"),
			OrigData:origData.String(),
		}
		mw.upModel.Items = append(mw.upModel.Items, du)
		mw.upModel.PublishRowsReset()
		_ = mw.upTv.SetSelectedIndexes([]int{})
		frames,_:= packet.GetUplinkFrames(true,false)
		for j := range frames {
			mw.PushData(mw.dtuConf.GatewayId,"up",&frames[j])
		}
		fmt.Println("push join ")
		for cnt := 0;mw.dtuConf.DevAddr == "" && cnt < 5;cnt ++ {
			time.Sleep(time.Second)
		}
		if mw.dtuConf.DevAddr != "" {
			fmt.Println("join ok")
		}else{
			fmt.Println("join failed")
			return
		}
	}
	packet,phy := mw.BuildUpData()
	var origData bytes.Buffer
	jsonData,_ := phy.MarshalJSON()
	_ = json.Indent(&origData, jsonData, "", "  ")
	du := &model.DTUUp{
		Index:mw.upModel.Len() + 1,
		DevEUI:mw.dtuConf.DevEui,
		MType:phy.MHDR.MType.String(),
		GatewayID:mw.dtuConf.GatewayId,
		Rssi:packet.Payload.RXPK[0].RSSI,
		LoRaSNR:packet.Payload.RXPK[0].LSNR,
		Frequency:packet.Payload.RXPK[0].Freq,
		FCnt:mw.dtuConf.FCnt,
		FPort:mw.dtuConf.FPort,
		HexData:hex.EncodeToString(mw.dtuConf.msg),
		AsciiData:BytesToString(mw.dtuConf.msg),
		Time:time.Now().Format("2006-01-02 15:04:05"),
		OrigData:origData.String(),
	}
	mw.upModel.Items = append(mw.upModel.Items, du)
	mw.upModel.PublishRowsReset()
	_ = mw.upTv.SetSelectedIndexes([]int{})
	frames,_:= packet.GetUplinkFrames(true,false)
	for j := range frames {
		mw.PushData(mw.dtuConf.GatewayId,"up",&frames[j])
	}
	mw.dtuConf.FCnt ++
	var confData bytes.Buffer
	d,_  := json.Marshal(&mw.dtuConf)
	_ = json.Indent(&confData, d, "", "\t")
	_ = ioutil.WriteFile(mw.dtuConfFileName,confData.Bytes(),0644)
}

func (mw *DTUMainWindow) upTvItemActivated() {
	msg := ""
	for _, i := range mw.upTv.SelectedIndexes() {
		msg += mw.upModel.Items[i].OrigData + "\n"
	}
	walk.MsgBox(mw, "原始数据", msg, walk.MsgBoxOK)
}

func (mw *DTUMainWindow) downTvItemActivated() {
	msg := ""
	for _, i := range mw.downTv.SelectedIndexes() {
		msg += mw.downModel.Items[i].OrigData + "\n"
	}
	walk.MsgBox(mw, "原始数据", msg, walk.MsgBoxOK)
}