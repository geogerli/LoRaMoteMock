package main

import (
	"github.com/brocaar/lorawan"
	"github.com/lxn/walk"
	"sort"
)

type ConnectConfig struct {
	Host 			string 	`json:"host"`
	Port 			int 	`json:"port"`
	Username 		string 	`json:"username"`
	Password 		string 	`json:"password"`
	SSL				bool 	`json:"ssl"`
	CACert 			string	`json:"ca_cert"`
	TLSCert 		string	`json:"tls_cert"`
	TLSKey 			string 	`json:"tls_key"`
	EventTopic 		string 	`json:"eventTopic"`
	CommandTopic 	string 	`json:"commandTopic"`
}

type MoteConfig struct {
	OTAA       bool          `json:"otaa"`
	GatewayEui string        `json:"gatewayEui"`
	AppEui     string        `json:"appEui"`
	DevEui     string        `json:"devEui"`
	DevAddr    string        `json:"devAddr"`
	AppKey     string        `json:"appKey"`
	NwkSKey    string        `json:"nwkSKey"`
	AppSKey    string        `json:"appSKey"`
	FCnt       uint32        `json:"fCnt"`
	FPort      uint8         `json:"fPort"`
	Freq       float64       `json:"freq"`
	DR         uint8         `json:"dr"`
	Chan       uint8         `json:"chan"`
	LSNR       float64       `json:"lsnr"`
	RSSI       int16         `json:"rssi"`
	MType      uint8         `json:"mType"`
	FCtrl      lorawan.FCtrl `json:"fCtrl"`
	devNonce  lorawan.DevNonce
}

type MotesConfig struct {
	Current 	string	`json:"current"`
	Configs 	map[string]MoteConfig `json:"configs"`
}


type Mote struct {
	Index   int
	Direction string
	DevEUI   string
	DevAddr string
	MType	string
	GatewayID string
	Rssi int16
	LoRaSNR float64
	Frequency float64
	FCnt uint32
	FPort uint8
	HexData string
	AsciiData string
	Time string
	checked bool
	OrigData string
}

type MoteModel struct {
	walk.TableModelBase
	walk.SorterBase
	SortColumn int
	SortOrder  walk.SortOrder
	Items      []*Mote
}

func (m *MoteModel) RowCount() int {
	return len(m.Items)
}

func (m *MoteModel) Value(row, col int) interface{} {
	item := m.Items[row]

	switch col {
	case 0:
		return item.Index
	case 1:
		return item.Direction
	case 2:
		return item.DevEUI
	case 3:
		return item.DevAddr
	case 4:
		return item.MType
	case 5:
		return item.GatewayID
	case 6:
		return item.Rssi
	case 7:
		return item.LoRaSNR
	case 8:
		return item.Frequency
	case 9:
		return item.FCnt
	case 10:
		return item.FPort
	case 11:
		return item.HexData
	case 12:
		return item.AsciiData
	case 13:
		return item.Time
	}
	panic("unexpected col")
}

func (m *MoteModel) Checked(row int) bool {
	return m.Items[row].checked
}

func (m *MoteModel) SetChecked(row int, checked bool) error {
	m.Items[row].checked = checked
	return nil
}

func (m *MoteModel) Sort(col int, order walk.SortOrder) error {
	m.SortColumn, m.SortOrder = col, order
	sort.Stable(m)
	return m.SorterBase.Sort(col, order)
}

func (m *MoteModel) Len() int {
	return len(m.Items)
}

func (m *MoteModel) Less(i, j int) bool {
	a, b := m.Items[i], m.Items[j]
	c := func(ls bool) bool {
		if m.SortOrder == walk.SortAscending {
			return ls
		}
		return !ls
	}

	switch m.SortColumn {
	case 0:
		return c(a.Index < b.Index)
	case 1:
		return c(a.Direction < b.Direction)
	case 2:
		return c(a.DevEUI < b.DevEUI)
	case 3:
		return c(a.DevAddr < b.DevAddr)
	case 4:
		return c(a.MType < b.MType)
	case 5:
		return c(a.GatewayID < b.GatewayID)
	case 9:
		return c(a.FCnt < b.FCnt)
	case 10:
		return c(a.FPort < b.FPort)
	case 13:
		return c(a.Time < b.Time)
	default:
		return false
	}
}

func (m *MoteModel) Swap(i, j int) {
	m.Items[i], m.Items[j] = m.Items[j], m.Items[i]
}

func NewMoteModel() *MoteModel {
	return new(MoteModel)
}
