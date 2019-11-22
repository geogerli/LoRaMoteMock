package main

import (
	"fmt"
	"github.com/lxn/walk"
)

func FormatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type Node struct {
	name     string
	value	 interface{}
	parent   *Node
	children []*Node
}

func NewNode(name string,value interface{},parent *Node) *Node {
	return &Node{name: name,value:value,parent: parent}
}

func (d *Node) Text() string {
	txt := d.name
	dim := " : "
	switch d.value.(type) {
	case int,int8,int16,int32,int64,uint,uint8,uint16,uint32,uint64:
		txt += dim + fmt.Sprintf("%d",d.value)
	case float32,float64:
		txt += dim + fmt.Sprintf("%f",d.value)
	case string:
		txt += dim + "\"" + d.value.(string) + "\""
	case bool:
		txt += dim + FormatBool(d.value.(bool))
	case map[string]interface{}:
		txt += "(Object)"
	case []interface{}:
		txt += "(Array)"
	}
	return txt
}

func (d *Node) Parent() walk.TreeItem {
	if d.parent == nil {
		return nil
	}
	return d.parent
}

func (d *Node) ChildCount() int {
	if d.children == nil {
		d.ResetChildren();
	}
	return len(d.children)
}

func (d *Node) ChildAt(index int) walk.TreeItem {
	return d.children[index]
}

func (d *Node) Image() interface{} {
	icon,err := walk.NewIconFromResourceId(5)
	if err != nil {
		return ""
	}
	return icon
}

func (d *Node) ResetChildren() {
	d.children = nil
	switch d.value.(type) {
	case map[string]interface{}:
		m := d.value.(map[string]interface{})
		for k,v := range m {
			d.children = append(d.children, NewNode(k, v,d))
		}
	case []interface{}:
		v := d.value.([]interface{})
		for i,_ := range v {
			d.children = append(d.children, NewNode(fmt.Sprintf("%d",i), v[i],d))
		}
	}
}

type JSONModel struct {
	walk.TreeModelBase
	roots []*Node
}

func NewJSONModel(m map[string]interface{}) *JSONModel {
	model := new(JSONModel)
	for k,v := range m {
		model.roots = append(model.roots, NewNode(k, v,nil))
	}
	return model
}

func (*JSONModel) LazyPopulation() bool {
	return true
}

func (m *JSONModel) RootCount() int {
	return len(m.roots)
}

func (m *JSONModel) RootAt(index int) walk.TreeItem {
	return m.roots[index]
}