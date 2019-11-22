package main

import (
	"LoRaMoteMock/packets"
	"bytes"
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
	"strings"
	"time"
)

type MoteMainWindow struct {
	*walk.MainWindow
	mqttClient                      paho.Client
	model                           *MoteModel
	tv                              *walk.TableView
	jsonView                        *walk.TreeView
	host,username,password          *walk.LineEdit
	port,sendInterval               *walk.NumberEdit
	connect, disconnect,caConf,send *walk.PushButton
	ascii,noAscii                   *walk.RadioButton
	msg,data                        *walk.TextEdit
	ssl,timeSend                    *walk.CheckBox
	connConf                        ConnectConfig
	motesConf                       MotesConfig
	currentMoteConf                 MoteConfig
	connConfFileName                string
	moteConfFileName                string
	icon                            *walk.Icon
}

func main() {
	mw := &MoteMainWindow{model: NewMoteModel()}
	mw.icon,_ = walk.NewIconFromResourceId(3)
	maxWidth := int(win.GetSystemMetrics(win.SM_CXSCREEN)) - 200
	maxHeight := int(win.GetSystemMetrics(win.SM_CYSCREEN)) - 100
	err := MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "LoRaMoteMock",
		Icon:		mw.icon,
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
					PushButton{Text:"终端配置",OnClicked: mw.MoteConfig},
					PushButton{Text:"清空数据",OnClicked: mw.Clean},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					TableView{
						AssignTo:         &mw.tv,
						MinSize:Size{Width:maxWidth*3/5},
						ColumnsOrderable: true,
						MultiSelection:   true,
						Columns: []TableViewColumn{
							{Title: "序号"},
							{Title: "数据方向"},
							{Title: "终端EUI"},
							{Title: "终端地址"},
							{Title: "消息类型"},
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
						Model: mw.model,
						OnItemActivated: mw.tvItemActivated,
					},
					GroupBox{
						Title:"发送区",
						Layout:VBox{SpacingZero:true},
						Children:[]Widget{
							Composite{
								Layout:Grid{Columns:3},
								Children:[]Widget{
									Label{Text:"编码方式:"},
									RadioButton{Text:"ASCII数据",AssignTo:&mw.ascii},
									RadioButton{Text:"Hex数据",AssignTo:&mw.noAscii},

									CheckBox{Text:"定时发送",AssignTo:&mw.timeSend,OnClicked:mw.TimeSend},
									NumberEdit{AssignTo:&mw.sendInterval},
									Label{Text:"ms/次"},
								},
							},
							Composite{
								Layout:VBox{},
								Children:[]Widget{
									Label{Text:"消息"},
									TextEdit{AssignTo:&mw.msg},
								},
							},
							Composite{
								Layout:HBox{},
								Children:[]Widget{
									HSpacer{},
									PushButton{Text:"发送",AssignTo:&mw.send,OnClicked: mw.SendMsg},
								},
							},
						},
					},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					TextEdit{AssignTo:&mw.data,ReadOnly:true,HScroll:true,VScroll:true},
					TreeView{AssignTo: &mw.jsonView},
				},
			},
		},
	}.Create()
	if err != nil {
		panic("LoRaMoteMock窗口创建失败")
	}
	_ = mw.port.SetValue(1883)
	_ = mw.sendInterval.SetValue(1000)
	mw.ascii.SetChecked(true)
	dir,_ := os.Getwd()
	mw.connConfFileName = dir + "/LoRaMoteMock.json"
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
	mw.moteConfFileName = dir + "/LoRaMoteConf.json"
	mw.motesConf.Configs = make(map[string]MoteConfig)
	data, err = ioutil.ReadFile(mw.moteConfFileName)
	if err == nil {
		err = json.Unmarshal(data, &mw.motesConf)
		if err != nil {
			msg := "配置文件格式错误:" + err.Error()
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			return
		}
		mw.currentMoteConf = mw.motesConf.Configs[mw.motesConf.Current]
	}
	mw.Run()
}


func (mw *MoteMainWindow) Connect()  {
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

func (mw *MoteMainWindow) Disconnect()  {
	mw.connect.SetEnabled(true)
	mw.host.SetEnabled(true)
	mw.port.SetEnabled(true)
	mw.username.SetEnabled(true)
	mw.password.SetEnabled(true)
	mw.disconnect.SetEnabled(false)
	mw.caConf.SetEnabled(true)
	mw.mqttClient.Disconnect(0)
}

func (mw *MoteMainWindow) MoteConfig()  {
	var dlg *walk.Dialog
	var name *walk.ComboBox
	var otaa *walk.CheckBox
	var gatewayId,devEUI,devAddr,appKey,appSKey,nwkSKey *walk.LineEdit
	var fPort,fCnt,freq *walk.NumberEdit
	var acceptPB, cancelPB *walk.PushButton
	_ = Dialog{
		Title: "终端配置",
		Icon: mw.icon,
		Layout:   VBox{},
		AssignTo: &dlg,
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize: Size{400, 200},
		Children: []Widget{
			Composite{
				Layout:Grid{Columns: 2},
				Children:[]Widget{
					Label{Text: "终端名称:"},
					ComboBox{AssignTo: &name,Editable: true,OnCurrentIndexChanged: func() {
						mw.motesConf.Current = name.Text()
						mw.currentMoteConf = mw.motesConf.Configs[mw.motesConf.Current]
						otaa.SetChecked(mw.currentMoteConf.OTAA)
						_ = gatewayId.SetText(mw.currentMoteConf.GatewayId)
						_ = devEUI.SetText(mw.currentMoteConf.DevEui)
						_ = devAddr.SetText(mw.currentMoteConf.DevAddr)
						_ = appKey.SetText(mw.currentMoteConf.AppKey)
						_ = appSKey.SetText(mw.currentMoteConf.AppSKey)
						_ = nwkSKey.SetText(mw.currentMoteConf.NwkSKey)
						_ = fPort.SetValue(float64(mw.currentMoteConf.FPort))
						_ = fCnt.SetValue(float64(mw.currentMoteConf.FCnt))
						_ = freq.SetValue(mw.currentMoteConf.Freq)

					}},
					Label{Text:"入网方式:"},
					CheckBox{AssignTo: &otaa,Text:"OTAA入网",OnClicked: func() {
						if otaa.Checked() {
							appKey.SetEnabled(true)
							devAddr.SetEnabled(false)
							appSKey.SetEnabled(false)
							nwkSKey.SetEnabled(false)
							_ = devAddr.SetText("")
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
					Label{Text:"网络会话秘钥:"},
					LineEdit{AssignTo:&nwkSKey},
					Label{Text:"应用会话秘钥:"},
					LineEdit{AssignTo:&appSKey},
					Label{Text:"端口:"},
					NumberEdit{AssignTo:&fPort},
					Label{Text:"计数:"},
					NumberEdit{AssignTo:&fCnt},
					Label{Text:"频率:"},
					NumberEdit{AssignTo:&freq,Decimals:2},
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
							mw.currentMoteConf.OTAA = otaa.Checked()
							mw.currentMoteConf.GatewayId = gatewayId.Text()
							mw.currentMoteConf.DevEui = devEUI.Text()
							mw.currentMoteConf.DevAddr = devAddr.Text()
							mw.currentMoteConf.AppKey = appKey.Text()
							mw.currentMoteConf.AppSKey = appSKey.Text()
							mw.currentMoteConf.NwkSKey = nwkSKey.Text()
							mw.currentMoteConf.FPort = uint8(fPort.Value())
							mw.currentMoteConf.FCnt = uint32(fCnt.Value())
							mw.currentMoteConf.Freq = freq.Value()
							mw.motesConf.Current = name.Text()
							mw.motesConf.Configs[mw.motesConf.Current] = mw.currentMoteConf

							var confData bytes.Buffer
							d,_  := json.Marshal(&mw.motesConf)
							_ = json.Indent(&confData, d, "", "\t")
							_ = ioutil.WriteFile(mw.moteConfFileName,confData.Bytes(),0644)
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
	var names []string
	for k,_ := range mw.motesConf.Configs {
		names = append(names,k)
	}
	_ = name.SetModel(names)
	_ = name.SetText(mw.motesConf.Current)
	otaa.SetChecked(mw.currentMoteConf.OTAA)
	_ = gatewayId.SetText(mw.currentMoteConf.GatewayId)
	_ = devEUI.SetText(mw.currentMoteConf.DevEui)
	_ = devAddr.SetText(mw.currentMoteConf.DevAddr)
	_ = appKey.SetText(mw.currentMoteConf.AppKey)
	_ = appSKey.SetText(mw.currentMoteConf.AppSKey)
	_ = nwkSKey.SetText(mw.currentMoteConf.NwkSKey)
	_ = fPort.SetValue(float64(mw.currentMoteConf.FPort))
	_ = fCnt.SetValue(float64(mw.currentMoteConf.FCnt))
	_ = freq.SetValue(mw.currentMoteConf.Freq)

	dlg.Run()
}
func (mw *MoteMainWindow) Clean()  {
	mw.model.Items = []*Mote{}
	mw.model.PublishRowsReset()
	_ = mw.tv.SetSelectedIndexes([]int{})
}
func (mw *MoteMainWindow) SSL()  {
	if mw.ssl.Checked() {
		mw.caConf.SetEnabled(true)
	}else{
		mw.caConf.SetEnabled(false)
	}
}

func (mw *MoteMainWindow) ConnectConfig()  {
	var dlg *walk.Dialog
	var caCert,tlsCert,tlsKey *walk.LineEdit
	var acceptPB, cancelPB *walk.PushButton
	_ = Dialog{
		Title: "连接配置",
		Icon: mw.icon,
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

func (mw *MoteMainWindow) HandleData(client paho.Client, message paho.Message){
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
				dd := &Mote{
					Index: mw.model.Len() + 1,
					Direction:"downlink",
					DevEUI: mw.currentMoteConf.DevEui,
					DevAddr: mw.currentMoteConf.DevAddr,
					MType: phy.MHDR.MType.String(),
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
				mw.model.Items = append(mw.model.Items, dd)
				mw.model.PublishRowsReset()
				_ = mw.tv.SetSelectedIndexes([]int{})
			}
		}
	}
}

func (mw *MoteMainWindow) HandleJoinAccept(phy *lorawan.PHYPayload){
	key := mw.currentMoteConf.AppKey
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
	mw.currentMoteConf.DevAddr = jap.DevAddr.String()
	dn := mw.currentMoteConf.devNonce
	appSKey,err := getAppSKey(aseKey,jap.HomeNetID,jap.JoinNonce,dn)
	if err == nil {
		mw.currentMoteConf.AppSKey = appSKey.String()
		fmt.Println(mw.currentMoteConf.AppSKey)
	}
	nwkSKey,err := getNwkSKey(aseKey,jap.HomeNetID,jap.JoinNonce,dn)
	if err == nil {
		mw.currentMoteConf.NwkSKey = nwkSKey.String()
		fmt.Println(mw.currentMoteConf.NwkSKey)
	}
}

func (mw *MoteMainWindow) HandleDataDown(phy *lorawan.PHYPayload){
	mpl := phy.MACPayload.(*lorawan.MACPayload)
	key := mw.currentMoteConf.AppSKey
	if mpl.FPort != nil && *mpl.FPort == 0 {
		key = mw.currentMoteConf.NwkSKey
	}

	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(key))
	err := phy.DecryptFRMPayload(aseKey)
	if err == nil {
		mw.currentMoteConf.DevAddr = mpl.FHDR.DevAddr.String()
	}
}

func (mw *MoteMainWindow) PushData(gatewayEUI string,event string, msg proto.Message)  {
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
func (mw *MoteMainWindow) sendMsg() error{
	if mw.mqttClient == nil || !mw.mqttClient.IsConnected() {
		msg := "请先连接服务器"
		walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
		return errors.New("请先连接服务器")
	}
	if mw.currentMoteConf.OTAA && mw.currentMoteConf.DevAddr == ""{
		mw.currentMoteConf.devNonce = lorawan.DevNonce(rand.Uint32())
		appEui := "0807060504030201"
		packet,phy,_ := BuildJoin(mw.currentMoteConf.GatewayId,appEui,mw.currentMoteConf.DevEui,mw.currentMoteConf.AppKey,
			5,2,mw.currentMoteConf.Freq,7,-51, mw.currentMoteConf.devNonce)
		var origData bytes.Buffer
		jsonData,_ := phy.MarshalJSON()
		_ = json.Indent(&origData, jsonData, "", "  ")
		du := &Mote{
			Index:mw.model.Len() + 1,
			Direction:"uplink",
			DevEUI:mw.currentMoteConf.DevEui,
			MType:phy.MHDR.MType.String(),
			GatewayID:mw.currentMoteConf.GatewayId,
			Rssi:packet.Payload.RXPK[0].RSSI,
			LoRaSNR:packet.Payload.RXPK[0].LSNR,
			Frequency:packet.Payload.RXPK[0].Freq,
			Time:time.Now().Format("2006-01-02 15:04:05"),
			OrigData:origData.String(),
		}
		mw.model.Items = append(mw.model.Items, du)
		mw.model.PublishRowsReset()
		_ = mw.tv.SetSelectedIndexes([]int{})
		frames,_:= packet.GetUplinkFrames(true,false)
		for j := range frames {
			mw.PushData(mw.currentMoteConf.GatewayId,"up",&frames[j])
		}
		fmt.Println("push join ")
		for cnt := 0;mw.currentMoteConf.DevAddr == "" && cnt < 5;cnt ++ {
			time.Sleep(time.Second)
		}
		if mw.currentMoteConf.DevAddr != "" {
			fmt.Println("join ok")
		}else{
			fmt.Println("join failed")
			return errors.New("join failed")
		}
	}
	var bmsg []byte
	var err error
	if mw.ascii.Checked() {
		bmsg = []byte(mw.msg.Text())
	}else{
		bmsg,err = hex.DecodeString(mw.msg.Text())
		if err != nil {
			msg := "hex数据格式错误:" + err.Error()
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			return err
		}
	}
	var fCtrl lorawan.FCtrl
	_ = fCtrl.UnmarshalBinary([]byte{128})
	key := mw.currentMoteConf.AppSKey
	if mw.currentMoteConf.FPort == 0 {
		key = mw.currentMoteConf.NwkSKey
	}
	packet,phy,_ := BuildUpData(mw.currentMoteConf.GatewayId,mw.currentMoteConf.DevAddr,key,
		mw.currentMoteConf.NwkSKey,mw.currentMoteConf.FCnt,mw.currentMoteConf.FPort,5,2,mw.currentMoteConf.Freq,7,
		lorawan.UnconfirmedDataUp,fCtrl,-51,bmsg)

	var origData bytes.Buffer
	jsonData,_ := phy.MarshalJSON()
	_ = json.Indent(&origData, jsonData, "", "  ")
	du := &Mote{
		Index:mw.model.Len() + 1,
		Direction:"uplink",
		DevEUI:mw.currentMoteConf.DevEui,
		DevAddr:mw.currentMoteConf.DevAddr,
		MType:phy.MHDR.MType.String(),
		GatewayID:mw.currentMoteConf.GatewayId,
		Rssi:packet.Payload.RXPK[0].RSSI,
		LoRaSNR:packet.Payload.RXPK[0].LSNR,
		Frequency:packet.Payload.RXPK[0].Freq,
		FCnt:mw.currentMoteConf.FCnt,
		FPort:mw.currentMoteConf.FPort,
		HexData:hex.EncodeToString(bmsg),
		AsciiData:BytesToString(bmsg),
		Time:time.Now().Format("2006-01-02 15:04:05"),
		OrigData:origData.String(),
	}
	mw.model.Items = append(mw.model.Items, du)
	mw.model.PublishRowsReset()
	_ = mw.tv.SetSelectedIndexes([]int{})
	frames,_:= packet.GetUplinkFrames(true,false)
	for j := range frames {
		mw.PushData(mw.currentMoteConf.GatewayId,"up",&frames[j])
	}
	mw.currentMoteConf.FCnt ++
	var confData bytes.Buffer
	d,_  := json.Marshal(&mw.currentMoteConf)
	_ = json.Indent(&confData, d, "", "\t")
	_ = ioutil.WriteFile(mw.moteConfFileName,confData.Bytes(),0644)
	return nil
}

func (mw *MoteMainWindow) SendMsg() {
	go mw.sendMsg()
}
func (mw *MoteMainWindow) SetSend() {
	if mw.timeSend.Checked() {
		mw.ascii.SetEnabled(false)
		mw.noAscii.SetEnabled(false)
		mw.sendInterval.SetEnabled(false)
		mw.msg.SetEnabled(false)
		mw.send.SetEnabled(false)
	}else{
		mw.ascii.SetEnabled(true)
		mw.noAscii.SetEnabled(true)
		mw.sendInterval.SetEnabled(true)
		mw.msg.SetEnabled(true)
		mw.send.SetEnabled(true)
	}
}

func (mw *MoteMainWindow) TimeSend()  {
	if mw.sendInterval.Value() <= 0 {
		msg := "时间间隔需大于0"
		walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
		return
	}
	mw.SetSend()
	go func() {
		for{
			if !mw.timeSend.Checked() {
				break
			}
			if err := mw.sendMsg();err != nil {
				mw.timeSend.SetChecked(false)
				mw.SetSend()
				break
			}
			time.Sleep(time.Duration(mw.sendInterval.Value()) * time.Millisecond)
		}
	}()
}
func (mw *MoteMainWindow) tvItemActivated() {
	msg := ""
	for _, i := range mw.tv.SelectedIndexes() {
		msg += mw.model.Items[i].OrigData + "\n"
	}
	_ = mw.data.SetText(strings.Replace(msg, "\n", "\r\n", -1))

	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(msg), &m); err == nil {
		_ = mw.jsonView.SetModel(NewJSONModel(m))
	}
}