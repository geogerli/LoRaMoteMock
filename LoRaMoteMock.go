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
	mqttClient                         paho.Client
	model                              *MoteModel
	tv                                 *walk.TableView
	jsonView                           *walk.TreeView
	host,username,password             *walk.LineEdit
	port,sendInterval                  *walk.NumberEdit
	connect, disconnect, mqttConf,send *walk.PushButton
	ascii,noAscii                      *walk.RadioButton
	msg,data                           *walk.TextEdit
	timeSend                       	   *walk.CheckBox
	connConf                           ConnectConfig
	motesConf                          MotesConfig
	currentMoteConf                    MoteConfig
	connConfFileName                   string
	moteConfFileName                   string
	icon                               *walk.Icon
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
					PushButton{Text:"连接配置",AssignTo:&mw.mqttConf,OnClicked: mw.ConnectConfig},
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
						ContextMenuItems:[]MenuItem{
							Action{Text:"查看终端数据", OnTriggered: mw.tvItemActivated},
							Action{Text:"查看网关数据", OnTriggered: mw.tvItemGatewayActivated},
						},
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
					TreeView{AssignTo: &mw.jsonView,ContextMenuItems:[]MenuItem{
						Action{Text:"复制值", OnTriggered: mw.jsonItemCopy},
					}},
				},
			},
		},
	}.Create()
	if err != nil {
		panic("LoRaMoteMock窗口创建失败")
	}
	mw.connConf.EventTopic = "gateway/%s/event/%s"
	mw.connConf.CommandTopic = "gateway/+/command/#"
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
	//default
	mw.currentMoteConf.AppEui = "0102030405060708"
	mw.currentMoteConf.MType = uint8(lorawan.UnconfirmedDataUp)
	mw.currentMoteConf.FPort = 1
	mw.currentMoteConf.Freq = 470.3
	mw.currentMoteConf.RSSI = -50
	mw.currentMoteConf.LSNR = 7
	mw.currentMoteConf.FCtrl.ADR = true

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

	go mw.ConnectCheck()
	mw.Run()
	if mw.motesConf.Current != "" {
		var confData bytes.Buffer
		mw.motesConf.Configs[mw.motesConf.Current] = mw.currentMoteConf
		d,_  := json.Marshal(&mw.motesConf)
		_ = json.Indent(&confData, d, "", "\t")
		_ = ioutil.WriteFile(mw.moteConfFileName,confData.Bytes(),0644)
	}
}

func (mw *MoteMainWindow) ConnectCheck()  {
	for{
		if mw.mqttClient != nil && !mw.mqttClient.IsConnected() {
			mw.Disconnect()
		}
		time.Sleep(5 * time.Second)
	}
}

func (mw *MoteMainWindow) Connect()  {
	go func() {
		if mw.host.Text() != "" && mw.port.Value() > 0 {
			opts := paho.NewClientOptions()
			serverAddr := fmt.Sprintf("%s:%d",mw.host.Text(),int(mw.port.Value()))
			if mw.connConf.SSL {
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
				mw.mqttConf.SetEnabled(false)
				token := mw.mqttClient.Subscribe(mw.connConf.CommandTopic,0, mw.HandleData)
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
	mw.mqttConf.SetEnabled(true)
	mw.mqttClient.Disconnect(0)
}

func (mw *MoteMainWindow) MoteConfig() {
	var dlg *walk.Dialog
	var name *walk.ComboBox
	var otaa,join *walk.CheckBox

	var acceptPB, cancelPB *walk.PushButton
	var db *walk.DataBinder
	_ = Dialog{
		Title: "终端配置",
		Icon: mw.icon,
		Layout:   VBox{},
		AssignTo: &dlg,
		DataBinder: DataBinder{
			AssignTo:&db,
			Name:"config",
			DataSource: &mw.currentMoteConf,
			//ErrorPresenter: ToolTipErrorPresenter{},
		},
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize: Size{420, 400},
		Children: []Widget{
			TabWidget{
				Pages:[]TabPage{
					{
						Title:"基础配置",
						Layout:Grid{Columns: 3},
						Children:[]Widget{
							Label{Text: "配置名称:"},
							ComboBox{AssignTo: &name,Editable: true, OnCurrentIndexChanged: func() {
								mw.motesConf.Current = name.Text()
								mw.currentMoteConf = mw.motesConf.Configs[mw.motesConf.Current]
								_ = db.Reset()
							}},
							HSpacer{},
							Label{Text:"入网方式:"},
							Composite{
								Layout: HBox{},
								Children: []Widget{
									CheckBox{AssignTo: &otaa,Text:"OTAA入网",Checked:Bind("OTAA"),OnCheckStateChanged: func() {
										mw.currentMoteConf.OTAA = otaa.Checked()
										_ = db.Reset()
									}},
									CheckBox{AssignTo:&join,Text:"重新入网",Enabled:Bind("OTAA"),OnCheckStateChanged: func() {
										if mw.currentMoteConf.OTAA && join.Checked() {
											mw.currentMoteConf.DevAddr = ""
											mw.currentMoteConf.NwkSKey = ""
											mw.currentMoteConf.AppSKey = ""
											mw.currentMoteConf.FCnt = 0
											_ = db.Reset()
										}
									}},
								},
							},
							HSpacer{},
							Label{Text:"网关EUI:"},
							LineEdit{Text:Bind("GatewayEui",Regexp{Pattern:"^[0-9a-fA-F]{16,16}$"})},
							PushButton{Text:"随机",OnClicked: func() {
								mw.currentMoteConf.GatewayEui = GetRandomHexString(16)
								_ = db.Reset()
							}},
							Label{Text:"应用EUI:",Visible:Bind("OTAA")},
							LineEdit{Text:Bind("AppEui"),Visible:Bind("OTAA")},
							PushButton{Text:"随机",Visible:Bind("OTAA"),OnClicked: func() {
								mw.currentMoteConf.AppEui = GetRandomHexString(16)
								_ = db.Reset()
							}},
							Label{Text:"终端EUI:"},
							LineEdit{Text:Bind("DevEui",Regexp{Pattern:"^[0-9a-fA-F]{16,16}$"})},
							PushButton{Text:"随机",OnClicked: func() {
								mw.currentMoteConf.DevEui = GetRandomHexString(16)
								_ = db.Reset()
							}},
							Label{Text:"应用秘钥:",Visible:Bind("OTAA")},
							LineEdit{Text:Bind("AppKey"),Visible:Bind("OTAA")},
							PushButton{Text:"随机",Visible:Bind("OTAA"),OnClicked: func() {
								mw.currentMoteConf.AppKey = GetRandomHexString(32)
								_ = db.Reset()
							}},
							Label{Text:"终端地址:"},
							LineEdit{Text:Bind("DevAddr"),ReadOnly:Bind("OTAA")},
							PushButton{Text:"随机",OnClicked: func() {
								mw.currentMoteConf.DevAddr = GetRandomHexString(8)
								_ = db.Reset()
							}},
							Label{Text:"网络会话秘钥:"},
							LineEdit{Text:Bind("NwkSKey"),ReadOnly:Bind("OTAA")},
							PushButton{Text:"随机",OnClicked: func() {
								mw.currentMoteConf.NwkSKey = GetRandomHexString(32)
								_ = db.Reset()
							}},
							Label{Text:"应用会话秘钥:"},
							LineEdit{Text:Bind("AppSKey"),ReadOnly:Bind("OTAA")},
							PushButton{Text:"随机",OnClicked: func() {
								mw.currentMoteConf.AppSKey = GetRandomHexString(32)
								_ = db.Reset()
							}},
							Label{Text:"上行计数:"},
							NumberEdit{Value:Bind("FCnt")},
							HSpacer{},
						},
					},
					{
						Title:"高级配置",
						Layout:Grid{Columns: 2},
						Children:[]Widget{
							Label{Text:"消息类型:"},
							ComboBox{Model:[]struct {
								Id uint8
								Name string
							}{
								{2,"UnconfirmedDataUp"},
								{4,"ConfirmedDataUp"},
							},BindingMember: "Id", DisplayMember: "Name", Value: Bind("MType")},
							Label{Text:"扩频因子:"},
							ComboBox{Model:[]struct{
								Id uint8
								Name string
								}{
									{0,"SF12"},
									{1,"SF11"},
									{2,"SF10"},
									{3,"SF9"},
									{4,"SF8"},
									{5,"SF7"},
								},BindingMember: "Id", DisplayMember: "Name",Value:Bind("DR")},
							Label{Text:"端口:"},
							NumberEdit{Value:Bind("FPort")},
							Label{Text:"频率:"},
							NumberEdit{Decimals:2,Value:Bind("Freq")},
							Label{Text:"信道:"},
							NumberEdit{Value:Bind("Chan")},
							Label{Text:"信号强度:"},
							NumberEdit{Value:Bind("RSSI")},
							Label{Text:"信噪比:"},
							NumberEdit{Value:Bind("LSNR")},
							Label{Text:"帧控制:"},
							GroupBox{
								Title:"FCtrl",
								Layout:Grid{Columns: 3},
								Children:[]Widget{
									CheckBox{Text:"adr",Checked:Bind("FCtrl.ADR")},
									CheckBox{Text:"req",Checked:Bind("FCtrl.ADRACKReq")},
									CheckBox{Text:"ack",Checked:Bind("FCtrl.ACK")},
									CheckBox{Text:"fPending",Checked:Bind("FCtrl.FPending")},
									CheckBox{Text:"classB",Checked:Bind("FCtrl.ClassB")},
								},
							},
						},
					},
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
							mw.motesConf.Current = name.Text()
							if mw.motesConf.Current == "" {
								msg := "配置名称不能为空"
								walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
								return
							}
							if db.CanSubmit() {
								_ = db.Submit()
							}
							
							v,ok := mw.motesConf.Configs[mw.motesConf.Current]
							if ok {
								if mw.currentMoteConf.OTAA && v.OTAA != mw.currentMoteConf.OTAA {
									mw.currentMoteConf.DevAddr = ""
									mw.currentMoteConf.NwkSKey = ""
									mw.currentMoteConf.AppSKey = ""
									mw.currentMoteConf.FCnt = 0
								}
							}
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
	dlg.Run()
}

func (mw *MoteMainWindow) Clean()  {
	mw.model.Items = []*Mote{}
	mw.model.PublishRowsReset()
	_ = mw.tv.SetSelectedIndexes([]int{})
}

func (mw *MoteMainWindow) ConnectConfig()  {
	var dlg *walk.Dialog
	var ssl *walk.CheckBox
	var caCert,tlsCert,tlsKey *walk.LineEdit
	var acceptPB, cancelPB *walk.PushButton
	var db *walk.DataBinder
	_ = Dialog{
		Title: "连接配置",
		Icon: mw.icon,
		Layout:   VBox{},
		AssignTo: &dlg,
		DataBinder: DataBinder{
			AssignTo:&db,
			Name:"config",
			DataSource: &mw.connConf,
			ErrorPresenter: ToolTipErrorPresenter{},
		},
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize: Size{400, 200},
		Children: []Widget{
			Composite{
				Layout:Grid{Columns: 3},
				Children:[]Widget{
					Label{Text:"事件主题:"},
					LineEdit{Text:Bind("EventTopic")},
					HSpacer{},
					Label{Text:"命令主题:"},
					LineEdit{Text:Bind("CommandTopic")},
					HSpacer{},
					Label{Text:"SSL配置:"},
					CheckBox{Text:"开启SSL/TLS",AssignTo:&ssl,Checked:Bind("SSL"),OnCheckStateChanged: func() {
						mw.connConf.SSL = ssl.Checked()
						_ = db.Reset()
					}},
					HSpacer{},
					Label{Text:"CA证书:"},
					LineEdit{Text:Bind("CACert"),AssignTo:&caCert,Enabled:Bind("SSL")},
					PushButton{Text:"打开",Enabled:Bind("SSL"),OnClicked: func() {
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
					LineEdit{Text:Bind("TLSCert"),AssignTo:&tlsCert,Enabled:Bind("SSL")},
					PushButton{Text:"打开",Enabled:Bind("SSL"),OnClicked: func() {
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
					LineEdit{Text:Bind("TLSKey"),AssignTo:&tlsKey,Enabled:Bind("SSL")},
					PushButton{Text:"打开",Enabled:Bind("SSL"),OnClicked: func() {
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
							_ = db.Submit()
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
					if !mw.HandleDataDown(&phy) {
						return
					}
				default:
					fmt.Println("未处理的帧")
				}
				var origData bytes.Buffer
				jsonData,_ := phy.MarshalJSON()
				_ = json.Indent(&origData, jsonData, "", "  ")
				d,_ := json.MarshalIndent(&downlinkFrame,"","  ")
				dd := &Mote{
					Index:        mw.model.Len() + 1,
					Direction:    "downlink",
					DevEUI:       mw.currentMoteConf.DevEui,
					DevAddr:      mw.currentMoteConf.DevAddr,
					MType:        phy.MHDR.MType.String(),
					GatewayID:    hex.EncodeToString(downlinkFrame.TxInfo.GatewayId),
					Time:         time.Now().Format("2006-01-02 15:04:05"),
					MoteOrigData: origData.String(),
					GatewayOrigData: string(d),
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

func (mw *MoteMainWindow) HandleDataDown(phy *lorawan.PHYPayload) bool{
	mpl := phy.MACPayload.(*lorawan.MACPayload)
	key := mw.currentMoteConf.AppSKey
	if mpl.FPort != nil && *mpl.FPort == 0 {
		key = mw.currentMoteConf.NwkSKey
	}

	var aseKey lorawan.AES128Key
	_ = aseKey.UnmarshalText([]byte(key))
	err := phy.DecryptFRMPayload(aseKey)
	if err == nil {
		if mw.currentMoteConf.DevAddr == mpl.FHDR.DevAddr.String() {
			return true
		}
	}
	return false
}

func (mw *MoteMainWindow) PushData(gatewayEUI string,event string, msg proto.Message)  {
	topic := fmt.Sprintf(mw.connConf.EventTopic,gatewayEUI,event)
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
		return errors.New(msg)
	}
	if mw.currentMoteConf.OTAA && mw.currentMoteConf.DevAddr == ""{
		mw.currentMoteConf.devNonce = lorawan.DevNonce(rand.Uint32())
		packet,phy,err := BuildJoin(mw.currentMoteConf.GatewayEui,mw.currentMoteConf.AppEui,
			mw.currentMoteConf.DevEui,mw.currentMoteConf.AppKey,mw.currentMoteConf.DR,
			mw.currentMoteConf.Chan,mw.currentMoteConf.Freq,mw.currentMoteConf.LSNR,
			mw.currentMoteConf.RSSI, mw.currentMoteConf.devNonce)
		if err != nil {
			msg := "构建入网包错误:" + err.Error()
			walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
			return err
		}
		frames,_:= packet.GetUplinkFrames(true,false)
		var origData bytes.Buffer
		jsonData,_ := phy.MarshalJSON()
		_ = json.Indent(&origData, jsonData, "", "  ")
		d,_ :=  json.MarshalIndent(&frames[0],"","  ")
		du := &Mote{
			Index:        mw.model.Len() + 1,
			Direction:    "uplink",
			DevEUI:       mw.currentMoteConf.DevEui,
			MType:        phy.MHDR.MType.String(),
			GatewayID:    mw.currentMoteConf.GatewayEui,
			Rssi:         packet.Payload.RXPK[0].RSSI,
			LoRaSNR:      packet.Payload.RXPK[0].LSNR,
			Frequency:    packet.Payload.RXPK[0].Freq,
			Time:         time.Now().Format("2006-01-02 15:04:05"),
			MoteOrigData: origData.String(),
			GatewayOrigData:string(d),
		}
		mw.model.Items = append(mw.model.Items, du)
		mw.model.PublishRowsReset()
		_ = mw.tv.SetSelectedIndexes([]int{})

		for j := range frames {
			mw.PushData(mw.currentMoteConf.GatewayEui,"up",&frames[j])
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
	key := mw.currentMoteConf.AppSKey
	if mw.currentMoteConf.FPort == 0 {
		key = mw.currentMoteConf.NwkSKey
	}
	packet,phy,err := BuildUpData(mw.currentMoteConf.GatewayEui,mw.currentMoteConf.DevAddr,key,
		mw.currentMoteConf.NwkSKey,mw.currentMoteConf.FCnt,mw.currentMoteConf.FPort,
		mw.currentMoteConf.DR,mw.currentMoteConf.Chan,mw.currentMoteConf.Freq,mw.currentMoteConf.LSNR,
		lorawan.MType(mw.currentMoteConf.MType),mw.currentMoteConf.FCtrl,mw.currentMoteConf.RSSI,bmsg)
	if err != nil {
		msg := "构建上行包错误:" + err.Error()
		walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
		return err
	}
	frames,_:= packet.GetUplinkFrames(true,false)
	var origData bytes.Buffer
	jsonData,_ := phy.MarshalJSON()
	_ = json.Indent(&origData, jsonData, "", "  ")
	d,_ :=  json.MarshalIndent(&frames[0],"","  ")
	du := &Mote{
		Index:        mw.model.Len() + 1,
		Direction:    "uplink",
		DevEUI:       mw.currentMoteConf.DevEui,
		DevAddr:      mw.currentMoteConf.DevAddr,
		MType:        phy.MHDR.MType.String(),
		GatewayID:    mw.currentMoteConf.GatewayEui,
		Rssi:         packet.Payload.RXPK[0].RSSI,
		LoRaSNR:      packet.Payload.RXPK[0].LSNR,
		Frequency:    packet.Payload.RXPK[0].Freq,
		FCnt:         mw.currentMoteConf.FCnt,
		FPort:        mw.currentMoteConf.FPort,
		HexData:      hex.EncodeToString(bmsg),
		AsciiData:    BytesToString(bmsg),
		Time:         time.Now().Format("2006-01-02 15:04:05"),
		MoteOrigData: origData.String(),
		GatewayOrigData:string(d),
	}
	mw.model.Items = append(mw.model.Items, du)
	mw.model.PublishRowsReset()
	_ = mw.tv.SetSelectedIndexes([]int{})
	for j := range frames {
		mw.PushData(mw.currentMoteConf.GatewayEui,"up",&frames[j])
	}
	mw.currentMoteConf.FCnt ++
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
		msg += mw.model.Items[i].MoteOrigData + "\n"
	}
	_ = mw.data.SetText(strings.Replace(msg, "\n", "\r\n", -1))

	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(msg), &m); err == nil {
		_ = mw.jsonView.SetModel(NewJSONModel(m))
	}
}
func (mw *MoteMainWindow) tvItemGatewayActivated() {
	msg := ""
	for _, i := range mw.tv.SelectedIndexes() {
		msg += mw.model.Items[i].GatewayOrigData + "\n"
	}
	_ = mw.data.SetText(strings.Replace(msg, "\n", "\r\n", -1))

	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(msg), &m); err == nil {
		_ = mw.jsonView.SetModel(NewJSONModel(m))
	}
}

func (mw *MoteMainWindow) jsonItemCopy(){
	msg := mw.jsonView.CurrentItem().Text()
	if strings.Contains(msg,":") {
		msgs := strings.Split(msg,":")
		msg = msgs[1]
		msg = strings.Trim(msg," ")
		msg = strings.Trim(msg,"\"")
	}
	if err := walk.Clipboard().SetText(msg); err != nil {
		msg := "复制错误:" + err.Error()
		walk.MsgBox(mw, "错误", msg, walk.MsgBoxIconError)
	}
}