// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v3.21.12
// source: internal/proto/fsmon.proto

package fsmon

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// FsMon is the data from a single fsmon event
type FsMon struct {
	state                   protoimpl.MessageState `protogen:"open.v1"`
	Timestamp               *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	EventType               string                 `protobuf:"bytes,2,opt,name=event_type,json=eventType,proto3" json:"event_type,omitempty"`
	Name                    string                 `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Pid                     int32                  `protobuf:"varint,4,opt,name=pid,proto3" json:"pid,omitempty"`
	File                    string                 `protobuf:"bytes,5,opt,name=file,proto3" json:"file,omitempty"`
	Cmd                     string                 `protobuf:"bytes,6,opt,name=cmd,proto3" json:"cmd,omitempty"`
	ProcName                string                 `protobuf:"bytes,7,opt,name=proc_name,json=procName,proto3" json:"proc_name,omitempty"`
	Path                    string                 `protobuf:"bytes,8,opt,name=path,proto3" json:"path,omitempty"`
	Ppid                    int32                  `protobuf:"varint,9,opt,name=ppid,proto3" json:"ppid,omitempty"`
	Uid                     int32                  `protobuf:"varint,10,opt,name=uid,proto3" json:"uid,omitempty"`
	Gid                     int32                  `protobuf:"varint,11,opt,name=gid,proto3" json:"gid,omitempty"`
	Groups                  []int32                `protobuf:"varint,12,rep,packed,name=groups,proto3" json:"groups,omitempty"`
	CapEff                  string                 `protobuf:"bytes,13,opt,name=cap_eff,json=capEff,proto3" json:"cap_eff,omitempty"`
	CapPrm                  string                 `protobuf:"bytes,14,opt,name=cap_prm,json=capPrm,proto3" json:"cap_prm,omitempty"`
	CapBnd                  string                 `protobuf:"bytes,15,opt,name=cap_bnd,json=capBnd,proto3" json:"cap_bnd,omitempty"`
	Seccomp                 int32                  `protobuf:"varint,16,opt,name=seccomp,proto3" json:"seccomp,omitempty"`
	NoNewPrivs              int32                  `protobuf:"varint,17,opt,name=no_new_privs,json=noNewPrivs,proto3" json:"no_new_privs,omitempty"`
	Threads                 int32                  `protobuf:"varint,18,opt,name=threads,proto3" json:"threads,omitempty"`
	VmSize                  int32                  `protobuf:"varint,19,opt,name=vm_size,json=vmSize,proto3" json:"vm_size,omitempty"`
	VmRss                   int32                  `protobuf:"varint,20,opt,name=vm_rss,json=vmRss,proto3" json:"vm_rss,omitempty"`
	VmData                  int32                  `protobuf:"varint,21,opt,name=vm_data,json=vmData,proto3" json:"vm_data,omitempty"`
	VoluntaryCtxSwitches    int64                  `protobuf:"varint,22,opt,name=voluntary_ctx_switches,json=voluntaryCtxSwitches,proto3" json:"voluntary_ctx_switches,omitempty"`
	NonvoluntaryCtxSwitches int64                  `protobuf:"varint,23,opt,name=nonvoluntary_ctx_switches,json=nonvoluntaryCtxSwitches,proto3" json:"nonvoluntary_ctx_switches,omitempty"`
	ComputerId              string                 `protobuf:"bytes,24,opt,name=computer_id,json=computerId,proto3" json:"computer_id,omitempty"`
	unknownFields           protoimpl.UnknownFields
	sizeCache               protoimpl.SizeCache
}

func (x *FsMon) Reset() {
	*x = FsMon{}
	mi := &file_internal_proto_fsmon_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FsMon) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FsMon) ProtoMessage() {}

func (x *FsMon) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fsmon_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FsMon.ProtoReflect.Descriptor instead.
func (*FsMon) Descriptor() ([]byte, []int) {
	return file_internal_proto_fsmon_proto_rawDescGZIP(), []int{0}
}

func (x *FsMon) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *FsMon) GetEventType() string {
	if x != nil {
		return x.EventType
	}
	return ""
}

func (x *FsMon) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *FsMon) GetPid() int32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *FsMon) GetFile() string {
	if x != nil {
		return x.File
	}
	return ""
}

func (x *FsMon) GetCmd() string {
	if x != nil {
		return x.Cmd
	}
	return ""
}

func (x *FsMon) GetProcName() string {
	if x != nil {
		return x.ProcName
	}
	return ""
}

func (x *FsMon) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *FsMon) GetPpid() int32 {
	if x != nil {
		return x.Ppid
	}
	return 0
}

func (x *FsMon) GetUid() int32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *FsMon) GetGid() int32 {
	if x != nil {
		return x.Gid
	}
	return 0
}

func (x *FsMon) GetGroups() []int32 {
	if x != nil {
		return x.Groups
	}
	return nil
}

func (x *FsMon) GetCapEff() string {
	if x != nil {
		return x.CapEff
	}
	return ""
}

func (x *FsMon) GetCapPrm() string {
	if x != nil {
		return x.CapPrm
	}
	return ""
}

func (x *FsMon) GetCapBnd() string {
	if x != nil {
		return x.CapBnd
	}
	return ""
}

func (x *FsMon) GetSeccomp() int32 {
	if x != nil {
		return x.Seccomp
	}
	return 0
}

func (x *FsMon) GetNoNewPrivs() int32 {
	if x != nil {
		return x.NoNewPrivs
	}
	return 0
}

func (x *FsMon) GetThreads() int32 {
	if x != nil {
		return x.Threads
	}
	return 0
}

func (x *FsMon) GetVmSize() int32 {
	if x != nil {
		return x.VmSize
	}
	return 0
}

func (x *FsMon) GetVmRss() int32 {
	if x != nil {
		return x.VmRss
	}
	return 0
}

func (x *FsMon) GetVmData() int32 {
	if x != nil {
		return x.VmData
	}
	return 0
}

func (x *FsMon) GetVoluntaryCtxSwitches() int64 {
	if x != nil {
		return x.VoluntaryCtxSwitches
	}
	return 0
}

func (x *FsMon) GetNonvoluntaryCtxSwitches() int64 {
	if x != nil {
		return x.NonvoluntaryCtxSwitches
	}
	return 0
}

func (x *FsMon) GetComputerId() string {
	if x != nil {
		return x.ComputerId
	}
	return ""
}

type FsMonBatch struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Items         []*FsMon               `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FsMonBatch) Reset() {
	*x = FsMonBatch{}
	mi := &file_internal_proto_fsmon_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FsMonBatch) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FsMonBatch) ProtoMessage() {}

func (x *FsMonBatch) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fsmon_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FsMonBatch.ProtoReflect.Descriptor instead.
func (*FsMonBatch) Descriptor() ([]byte, []int) {
	return file_internal_proto_fsmon_proto_rawDescGZIP(), []int{1}
}

func (x *FsMonBatch) GetItems() []*FsMon {
	if x != nil {
		return x.Items
	}
	return nil
}

type Ack struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Message       string                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Ack) Reset() {
	*x = Ack{}
	mi := &file_internal_proto_fsmon_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Ack) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Ack) ProtoMessage() {}

func (x *Ack) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fsmon_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Ack.ProtoReflect.Descriptor instead.
func (*Ack) Descriptor() ([]byte, []int) {
	return file_internal_proto_fsmon_proto_rawDescGZIP(), []int{2}
}

func (x *Ack) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_internal_proto_fsmon_proto protoreflect.FileDescriptor

const file_internal_proto_fsmon_proto_rawDesc = "" +
	"\n" +
	"\x1ainternal/proto/fsmon.proto\x12\x05fsmon\x1a\x1fgoogle/protobuf/timestamp.proto\"\xaa\x05\n" +
	"\x05FsMon\x128\n" +
	"\ttimestamp\x18\x01 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x12\x1d\n" +
	"\n" +
	"event_type\x18\x02 \x01(\tR\teventType\x12\x12\n" +
	"\x04name\x18\x03 \x01(\tR\x04name\x12\x10\n" +
	"\x03pid\x18\x04 \x01(\x05R\x03pid\x12\x12\n" +
	"\x04file\x18\x05 \x01(\tR\x04file\x12\x10\n" +
	"\x03cmd\x18\x06 \x01(\tR\x03cmd\x12\x1b\n" +
	"\tproc_name\x18\a \x01(\tR\bprocName\x12\x12\n" +
	"\x04path\x18\b \x01(\tR\x04path\x12\x12\n" +
	"\x04ppid\x18\t \x01(\x05R\x04ppid\x12\x10\n" +
	"\x03uid\x18\n" +
	" \x01(\x05R\x03uid\x12\x10\n" +
	"\x03gid\x18\v \x01(\x05R\x03gid\x12\x16\n" +
	"\x06groups\x18\f \x03(\x05R\x06groups\x12\x17\n" +
	"\acap_eff\x18\r \x01(\tR\x06capEff\x12\x17\n" +
	"\acap_prm\x18\x0e \x01(\tR\x06capPrm\x12\x17\n" +
	"\acap_bnd\x18\x0f \x01(\tR\x06capBnd\x12\x18\n" +
	"\aseccomp\x18\x10 \x01(\x05R\aseccomp\x12 \n" +
	"\fno_new_privs\x18\x11 \x01(\x05R\n" +
	"noNewPrivs\x12\x18\n" +
	"\athreads\x18\x12 \x01(\x05R\athreads\x12\x17\n" +
	"\avm_size\x18\x13 \x01(\x05R\x06vmSize\x12\x15\n" +
	"\x06vm_rss\x18\x14 \x01(\x05R\x05vmRss\x12\x17\n" +
	"\avm_data\x18\x15 \x01(\x05R\x06vmData\x124\n" +
	"\x16voluntary_ctx_switches\x18\x16 \x01(\x03R\x14voluntaryCtxSwitches\x12:\n" +
	"\x19nonvoluntary_ctx_switches\x18\x17 \x01(\x03R\x17nonvoluntaryCtxSwitches\x12\x1f\n" +
	"\vcomputer_id\x18\x18 \x01(\tR\n" +
	"computerId\"0\n" +
	"\n" +
	"FsMonBatch\x12\"\n" +
	"\x05items\x18\x01 \x03(\v2\f.fsmon.FsMonR\x05items\"\x1f\n" +
	"\x03Ack\x12\x18\n" +
	"\amessage\x18\x01 \x01(\tR\amessage2\x9b\x01\n" +
	"\rFsMonIngestor\x12%\n" +
	"\tSendFsMon\x12\f.fsmon.FsMon\x1a\n" +
	".fsmon.Ack\x12/\n" +
	"\x0eSendFsMonBatch\x12\x11.fsmon.FsMonBatch\x1a\n" +
	".fsmon.Ack\x122\n" +
	"\x0fSendFsMonStream\x12\x11.fsmon.FsMonBatch\x1a\n" +
	".fsmon.Ack(\x01B&Z$blink-edr/internal/proto/fsmon;fsmonb\x06proto3"

var (
	file_internal_proto_fsmon_proto_rawDescOnce sync.Once
	file_internal_proto_fsmon_proto_rawDescData []byte
)

func file_internal_proto_fsmon_proto_rawDescGZIP() []byte {
	file_internal_proto_fsmon_proto_rawDescOnce.Do(func() {
		file_internal_proto_fsmon_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_internal_proto_fsmon_proto_rawDesc), len(file_internal_proto_fsmon_proto_rawDesc)))
	})
	return file_internal_proto_fsmon_proto_rawDescData
}

var file_internal_proto_fsmon_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_internal_proto_fsmon_proto_goTypes = []any{
	(*FsMon)(nil),                 // 0: fsmon.FsMon
	(*FsMonBatch)(nil),            // 1: fsmon.FsMonBatch
	(*Ack)(nil),                   // 2: fsmon.Ack
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_internal_proto_fsmon_proto_depIdxs = []int32{
	3, // 0: fsmon.FsMon.timestamp:type_name -> google.protobuf.Timestamp
	0, // 1: fsmon.FsMonBatch.items:type_name -> fsmon.FsMon
	0, // 2: fsmon.FsMonIngestor.SendFsMon:input_type -> fsmon.FsMon
	1, // 3: fsmon.FsMonIngestor.SendFsMonBatch:input_type -> fsmon.FsMonBatch
	1, // 4: fsmon.FsMonIngestor.SendFsMonStream:input_type -> fsmon.FsMonBatch
	2, // 5: fsmon.FsMonIngestor.SendFsMon:output_type -> fsmon.Ack
	2, // 6: fsmon.FsMonIngestor.SendFsMonBatch:output_type -> fsmon.Ack
	2, // 7: fsmon.FsMonIngestor.SendFsMonStream:output_type -> fsmon.Ack
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_internal_proto_fsmon_proto_init() }
func file_internal_proto_fsmon_proto_init() {
	if File_internal_proto_fsmon_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_internal_proto_fsmon_proto_rawDesc), len(file_internal_proto_fsmon_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internal_proto_fsmon_proto_goTypes,
		DependencyIndexes: file_internal_proto_fsmon_proto_depIdxs,
		MessageInfos:      file_internal_proto_fsmon_proto_msgTypes,
	}.Build()
	File_internal_proto_fsmon_proto = out.File
	file_internal_proto_fsmon_proto_goTypes = nil
	file_internal_proto_fsmon_proto_depIdxs = nil
}
