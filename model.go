package main

import (
	"github.com/brocaar/lorawan"
	"github.com/lxn/walk"
	"sort"
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

type DTU struct {
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

type DTUModel struct {
	walk.TableModelBase
	walk.SorterBase
	SortColumn int
	SortOrder  walk.SortOrder
	Items      []*DTU
}

func (m *DTUModel) RowCount() int {
	return len(m.Items)
}

func (m *DTUModel) Value(row, col int) interface{} {
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

func (m *DTUModel) Checked(row int) bool {
	return m.Items[row].checked
}

func (m *DTUModel) SetChecked(row int, checked bool) error {
	m.Items[row].checked = checked
	return nil
}

func (m *DTUModel) Sort(col int, order walk.SortOrder) error {
	m.SortColumn, m.SortOrder = col, order
	sort.Stable(m)
	return m.SorterBase.Sort(col, order)
}

func (m *DTUModel) Len() int {
	return len(m.Items)
}

func (m *DTUModel) Less(i, j int) bool {
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
	case 2:
		return c(a.DevEUI < b.DevEUI)
	case 4:
		return c(a.Rssi < b.Rssi)
	case 5:
		return c(a.LoRaSNR < b.LoRaSNR)
	case 6:
		return c(a.Frequency < b.Frequency)
	default:
		return false
	}
}

func (m *DTUModel) Swap(i, j int) {
	m.Items[i], m.Items[j] = m.Items[j], m.Items[i]
}

func NewDTUModel() *DTUModel {
	return new(DTUModel)
}
