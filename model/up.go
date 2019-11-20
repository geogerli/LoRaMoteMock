package model

import (
	"github.com/lxn/walk"
	"sort"
)

type DTUUp struct {
	Index   int
	DevEUI   string
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

type DTUUpModel struct {
	walk.TableModelBase
	walk.SorterBase
	SortColumn int
	SortOrder  walk.SortOrder
	Items      []*DTUUp
}

func (m *DTUUpModel) RowCount() int {
	return len(m.Items)
}

func (m *DTUUpModel) Value(row, col int) interface{} {
	item := m.Items[row]

	switch col {
	case 0:
		return item.Index
	case 1:
		return item.DevEUI
	case 2:
		return item.MType
	case 3:
		return item.GatewayID
	case 4:
		return item.Rssi
	case 5:
		return item.LoRaSNR
	case 6:
		return item.Frequency
	case 7:
		return item.FCnt
	case 8:
		return item.FPort
	case 9:
		return item.HexData
	case 10:
		return item.AsciiData
	case 11:
		return item.Time
	}
	panic("unexpected col")
}

func (m *DTUUpModel) Checked(row int) bool {
	return m.Items[row].checked
}

func (m *DTUUpModel) SetChecked(row int, checked bool) error {
	m.Items[row].checked = checked
	return nil
}

func (m *DTUUpModel) Sort(col int, order walk.SortOrder) error {
	m.SortColumn, m.SortOrder = col, order
	sort.Stable(m)
	return m.SorterBase.Sort(col, order)
}

func (m *DTUUpModel) Len() int {
	return len(m.Items)
}

func (m *DTUUpModel) Less(i, j int) bool {
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

func (m *DTUUpModel) Swap(i, j int) {
	m.Items[i], m.Items[j] = m.Items[j], m.Items[i]
}

func NewDTUUpModel() *DTUUpModel {
	return new(DTUUpModel)
}