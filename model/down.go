package model

import (
	"github.com/lxn/walk"
	"sort"
)

type DTUDown struct {
	Index   int
	DevEUI   string
	MType	string
	DevAddr string
	GatewayID string
	FCnt uint32
	FPort uint8
	HexData string
	AsciiData string
	Time string
	checked bool
	OrigData string
}

type DTUDownModel struct {
	walk.TableModelBase
	walk.SorterBase
	SortColumn int
	SortOrder  walk.SortOrder
	Items      []*DTUDown
}

func (m *DTUDownModel) RowCount() int {
	return len(m.Items)
}

func (m *DTUDownModel) Value(row, col int) interface{} {
	item := m.Items[row]

	switch col {
	case 0:
		return item.Index
	case 1:
		return item.DevEUI
	case 2:
		return item.MType
	case 3:
		return item.DevAddr
	case 4:
		return item.GatewayID
	case 5:
		return item.FCnt
	case 6:
		return item.FPort
	case 7:
		return item.HexData
	case 8:
		return item.AsciiData
	case 9:
		return item.Time
	}
	panic("unexpected col")
}

func (m *DTUDownModel) Checked(row int) bool {
	return m.Items[row].checked
}

func (m *DTUDownModel) SetChecked(row int, checked bool) error {
	m.Items[row].checked = checked
	return nil
}

func (m *DTUDownModel) Sort(col int, order walk.SortOrder) error {
	m.SortColumn, m.SortOrder = col, order
	sort.Stable(m)
	return m.SorterBase.Sort(col, order)
}

func (m *DTUDownModel) Len() int {
	return len(m.Items)
}

func (m *DTUDownModel) Less(i, j int) bool {
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
	default:
		return false
	}
}

func (m *DTUDownModel) Swap(i, j int) {
	m.Items[i], m.Items[j] = m.Items[j], m.Items[i]
}

func NewDTUDownModel() *DTUDownModel {
	return new(DTUDownModel)
}