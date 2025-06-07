package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type EBPFModule struct {
	Collection *ebpf.Collection
	Specs      *ebpf.CollectionSpec
}

// Load loads an eBPF object from path
func Load(path string) (*EBPFModule, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("loading collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}

	return &EBPFModule{
		Collection: coll,
		Specs:      spec,
	}, nil
}

// Program returns a loaded eBPF program by name
func (m *EBPFModule) Program(name string) (*ebpf.Program, error) {
	prog := m.Collection.Programs[name]
	if prog == nil {
		return nil, fmt.Errorf("program %s not found", name)
	}

	return prog, nil
}

// Map returns a loaded BPF map by name
func (m *EBPFModule) Map(name string) (*ebpf.Map, error) {
	bpfMap := m.Collection.Maps[name]

	if bpfMap == nil {
		return nil, fmt.Errorf("map %s not found", name)
	}

	return bpfMap, nil
}

func (m *EBPFModule) Close() {
	m.Collection.Close()
}
